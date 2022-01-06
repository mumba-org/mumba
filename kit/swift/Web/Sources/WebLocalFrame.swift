// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Graphics
import Compositor
import Javascript

public class WebLocalFrame : WebFrame {

    public var securityOrigin: WebSecurityOrigin { 
        let origin = _WebLocalFrameGetSecurityOrigin(reference)
        return WebSecurityOrigin(reference: origin!)
    }
        
    public var name: String {         
        get {
            return assignedName
        }
        set (newName){
            newName.withCString { strbuf in
                _WebLocalFrameSetName(reference, strbuf)
            }
        }
    }

    public var frameWidget: WebFrameWidget? {
      let ref = _WebLocalFrameGetFrameWidget(reference)
      //print("WebLocalFrame.frameWidget getter: returned \(ref)")
      return ref != nil ? WebFrameWidget(reference: ref!) : nil 
    }

    public var inputMethodController: WebInputMethodController? {
      let ref = _WebLocalFrameGetInputMethodController(reference)
      return ref != nil ? WebInputMethodController(frame: self, reference: ref!) : nil
    }
    
    public var assignedName: String {
      var len: CInt = 0
      let cstr = _WebLocalFrameAssignedName(reference, &len)
      return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
    }
    
    public var scrollOffset: IntSize { 
        get {
            var width: Int32 = 0, height: Int32 = 0
            _WebLocalFrameScrollOffset(reference, &width, &height)
            return IntSize(width: Int(width), height: Int(height))
        }
        set (offset) { 
            _WebLocalFrameSetScrollOffset(reference, Int32(offset.width), Int32(offset.height))
        }
    }
    
    public var documentSize: IntSize {
        var width: Int32 = 0, height: Int32 = 0
        _WebLocalFrameDocumentSize(reference, &width, &height)
        return IntSize(width: Int(width), height: Int(height))
    }
    
    public var hasVisibleContent: Bool {
        return _WebLocalFrameHasVisibleContent(reference) == 0 ? false : true
    }
    
    public var visibleContentRect: IntRect {
        var x: Int32 = 0, y: Int32 = 0, width: Int32 = 0, height: Int32 = 0
        _WebLocalFrameVisibleContentRect(reference, &x, &y, &width, &height)
        return IntRect(x: Int(x), y: Int(y), width: Int(width), height: Int(height))
    }
    
    public var canHaveScrollbars: Bool { 
    
        get {
            return _canHaveScrollbars
        }
        set (value) {
            _canHaveScrollbars = value
            _WebLocalFrameSetCanHaveScrollbars(reference, _canHaveScrollbars ? 1 : 0)
        }

    }

    public var isSelectionAnchorFirst: Bool {
      return _WebLocalFrameIsSelectionAnchorFirst(reference) != 0
    }

    public var documentLoader: WebDocumentLoader {
      //if let ref = _WebLocalFrameGetDocumentLoader(reference) {
      //  return WebDocumentLoader(reference: ref)
      //}
      //return nil
      if let loader = _documentLoader {
        return loader
      }
      let ref = _WebLocalFrameGetDocumentLoader(reference)
      _documentLoader = WebDocumentLoader(reference: ref!)
      return _documentLoader!
    }

    public var provisionalDocumentLoader: WebDocumentLoader? {
      if let ref = _WebLocalFrameGetProvisionalDocumentLoader(reference) {
        return WebDocumentLoader(reference: ref)
      }
      return nil
    }

    public var mainWorldScriptContext: JavascriptContext {
      let ref = _WebLocalFrameMainWorldScriptContext(reference)
      let context = JavascriptContext(reference: ref!)
      JavascriptContext.instance = context
      return context
    }

    public var document: WebDocument {
      let ref = _WebLocalFrameDocument(reference)
      return WebDocument(reference: ref!)
    }
    
    public var hasSelection: Bool { 
      return _WebLocalFrameHasSelection(reference) == 0 ? false : true
    }
    
    public var selectionRange: TextRange { 
      var start: CInt = 0
      var end: CInt = 0
      _WebLocalFrameSelectionRange(reference, &start, &end)
      return TextRange(start: Int(start), end: Int(end))
    }

    public var frameSelection: WebFrameSelection {
      let ref = _WebLocalFrameGetSelection(reference)
      return WebFrameSelection(reference: ref!)
    }

    public var isLocalRoot: Bool {
      return _WebLocalFrameIsLocalRoot(reference) != 0
    }

    public var localRoot: WebLocalFrame? {
      let ref = _WebLocalFrameGetLocalRoot(reference)
      return ref == nil ? nil : WebLocalFrame(reference: ref!)
    }

    public var editor: WebEditor {
      return WebEditor(frame: self, reference: _WebLocalFrameGetEditor(reference)!)
    }
        
    public var hasViewSourceMode: Bool { 
        
        get {
            return _WebLocalFrameIsViewSourceModeEnabled(reference) == 0 ? false : true
        } 
        set (enable) {
            _WebLocalFrameEnableViewSourceMode(reference, enable ? 1 : 0)
        }

    }
    
    public var hasMarkedText: Bool { 
        return _WebLocalFrameHasMarkedText(reference) == 0 ? false : true
    }
    
    public var markedRange: TextRange { 
        var start: CInt = 0
        var end: CInt = 0
        _WebLocalFrameMarkedRange(reference, &start, &end)
        return TextRange(start: Int(start), end: Int(end))
    }
    
    public var isCaretVisible: Bool { 
        
        get {
            return caretVisibility == .Visible    
        }

        set {
            caretVisibility = newValue ? .Visible : .Hidden
            _WebLocalFrameSetCaretVisible(reference, newValue ? 1 : 0)
        }
    }

    public var autofillClient: WebAutofillClient? {
        get {
            let ref = _WebLocalFrameAutofillClient(reference)
            if ref == nil {
                return nil
            }
            return WebAutofillClient(reference: ref!)
        }
        set {
            if let client = newValue {
                _WebLocalFrameSetAutofillClient(reference, client.reference)
            } else {
                _WebLocalFrameSetAutofillClient(reference, nil)
            }
        }
    }
    
    public var isLoading: Bool {
        return _WebLocalFrameIsLoading(reference) == 0 ? false : true
    }

    public var effectiveSandboxFlags: WebSandboxFlags {
        let result = _WebLocalFrameEffectiveSandboxFlags(reference)
        return WebSandboxFlags(rawValue: Int(result.rawValue))
    }

    public var window: WebWindow {
      return WebWindow(reference: _WebLocalFrameGetDomWindow(reference))
    }

    public var caretVisibility: CaretVisibility
    public weak var client: WebLocalFrameClient?
    private var _canHaveScrollbars: Bool
    internal var _documentLoader: WebDocumentLoader?

    internal static func createMainFrame(view: WebView, client: WebLocalFrameClient, interfaceRegistry: WebInterfaceRegistry?) -> WebLocalFrame {
      return WebLocalFrame(view: view, client: client, interfaceRegistry: interfaceRegistry)
    }

    internal init(view: WebView, client: WebLocalFrameClient, interfaceRegistry: WebInterfaceRegistry?) {
      _canHaveScrollbars = true
      caretVisibility = .Hidden

      super.init()

      self.client = client
      let callbacks = createCallbacks(client: client)
      let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)      
      self.reference = createMainFrameNative(state: state, view: view, callbacks: callbacks, interfaceRegistry: interfaceRegistry)
    }

    internal override init(reference: WebFrameRef) {
      _canHaveScrollbars = true
      caretVisibility = .Hidden

      super.init(reference: reference)
    }

    deinit {
      _WebLocalFrameDestroy(reference)
    }

    public func iconUrls(iconTypesMask: Int) -> ContiguousArray<String> {
      //let maxUrls = 1000
      //var urls: [UnsafePointer<CChar>?] = []
      //var len: Int32 = 0
      let result = ContiguousArray<String>()

      //urls.reserveCapacity(maxUrls)

      //urls.withUnsafeMutableBufferPointer { buf in
      //  _WebLocalFrameIconURLS(reference, Int32(iconTypesMask), buf.baseAddress, &len)
      //}

      //result.reserveCapacity(Int(len))

      //for i in 0...Int(len) {
      //  if let cstring = urls[i] {
      //      result.append(String(cString: cstring))
      //  }
      //}
        
      return result
    }

    public func setRemoteWebLayer(layer: Compositor.Layer) {
      _WebLocalFrameSetRemoteWebLayer(reference, layer.reference)
    }

    public func setSharedWorkerRepositoryClient(client: WebSharedWorkerRepositoryClient) {
      _WebLocalFrameSetSharedWorkerRepositoryClient(reference, nil)
    }

    public func dispatchBeforeUnloadEvent(isReload: Bool) -> Bool {
      return _WebLocalFrameDispatchBeforeUnloadEvent(reference, isReload ? 1 : 0) == 0 ? false : true
    }
    
    public func dispatchUnloadEvent() {
      _WebLocalFrameDispatchUnloadEvent(reference)
    }

    public func executeScript(script: String) {
      script.withCString { strbuf in
        _WebLocalFrameExecuteScript(reference, strbuf)
      }
    }

    public func executeScriptInIsolatedWorld(worldId: Int, sources: [String], extensionGroup: Int) {
      var csources: [UnsafePointer<CChar>?] = []
      csources.reserveCapacity(sources.count)

      for source in sources {
          source.withCString { csource in
              csources.append(csource)
          }
      }

      csources.withUnsafeMutableBufferPointer { strbuf in
          _WebLocalFrameExecuteScriptInIsolatedWorld(reference, Int32(worldId), strbuf.baseAddress, UInt32(sources.count))
      }
    }

    public func setIsolatedWorldSecurityOrigin(worldId: Int, origin: WebSecurityOrigin) {
      _WebLocalFrameSetIsolatedWorldSecurityOrigin(reference, Int32(worldId), origin.reference)
    }

    public func setIsolatedWorldContentSecurityPolicy(worldId: Int, policy: String) {
      policy.withCString { strbuf in
        _WebLocalFrameSetIsolatedWorldContentSecurityPolicy(reference, Int32(worldId), strbuf)
      }
    }

    public func addMessageToConsole(message: WebConsoleMessage) {
      message.text.withCString { msgbuf in
        _WebLocalFrameAddMessageToConsole(reference, WebConsoleMessageLevelEnum(rawValue: UInt32(message.level.rawValue)), msgbuf)
      }
    }

    public func collectGarbage() {
      _WebLocalFrameCollectGarbage(reference)
    }

    public func executeScriptAndReturnValue(_ script: String) -> JavascriptValue? {
      let handle = script.withCString {
        return _WebLocalFrameExecuteScriptAndReturnValue(reference, $0)
      }
      return handle == nil ? nil : JavascriptValue(context: mainWorldScriptContext, reference: handle!)
    }

    public func executeScriptInIsolatedWorld(
      worldId: Int, 
      sources: [String],
      extensionGroup: Int) -> [JavascriptValue] {

      var handleCount: Int32 = 0
      var handles: [JavascriptDataRef?] = []
      var result: [JavascriptValue] = []
      var csources: [UnsafePointer<CChar>?] = []
      // make room in the internal buffer of the array
      handles.reserveCapacity(sources.count)
      csources.reserveCapacity(sources.count)

      for source in sources {
          source.withCString { csource in
            csources.append(csource)
          }
      }

      let csourcesOffset = csources.withUnsafeMutableBufferPointer { buf -> UnsafeMutablePointer<UnsafePointer<CChar>?>? in
        return buf.baseAddress
      }

      handles.withUnsafeMutableBufferPointer { hndlbuf in
        _WebLocalFrameExecuteScriptInIsolatedWorldValues(reference, Int32(worldId), csourcesOffset, UInt32(sources.count), hndlbuf.baseAddress, &handleCount)
      }

      let context = JavascriptContext.current
      for handle in handles {
        result.append(JavascriptValue(context: context, reference: handle!))
      }
      
      return result
    }

    public func callFunctionEvenIfScriptDisabled(
      function: JavascriptFunction,
      value: JavascriptValue,
      argv: [JavascriptValue]) -> JavascriptValue {

      var handles: [JavascriptDataRef?] = []
      handles.reserveCapacity(argv.count)

      for arg in argv {
          handles.append(arg.reference)
      }

      let resultHandle = handles.withUnsafeMutableBufferPointer { buf -> JavascriptDataRef in
          return _WebLocalFrameCallFunctionEvenIfScriptDisabled(reference, function.reference, value.reference, Int32(argv.count), buf.baseAddress)
      }

      return JavascriptValue(context: mainWorldScriptContext, reference: resultHandle)
    }

    public func reload(type: WebFrameLoadType) {
      _WebLocalFrameReload(reference, WebFrameLoadEnum(UInt32(type.rawValue)))
    }

    public func reloadWithOverrideURL(url: String, ignoreCache: Bool) {
      url.withCString { str in
          _WebLocalFrameReloadWithOverrideURL(reference, str, ignoreCache ? 1 : 0)
      }
    }

    public func loadRequest(request: WebURLRequest) {
      _WebLocalFrameLoadRequest(reference, request.reference)
    }

    public func loadData(data: WebData,
                         mimeType: String,
                         textEncoding: String,
                         baseURL: String,
                         unreachableURL: String?,
                         replace: Bool) {
      
      var unreachPtr: UnsafePointer<Int8>?
      if let uurl = unreachableURL {
        unreachPtr = uurl.withCString { (ubuf: UnsafePointer<Int8>?) -> UnsafePointer<Int8>? in
          return ubuf
        }
      }
      if let databuf = data.data?.bindMemory(to: Int8.self, capacity: data.size) {
        mimeType.withCString { mimebuf in
          textEncoding.withCString { textbuf in
              baseURL.withCString { basebuf in
                _WebLocalFrameLoadData(reference, databuf, data.size, mimebuf, textbuf, basebuf, unreachPtr ?? nil, replace ? 1 : 0)
              }
          }
        }
      }
    }

    public func loadData(string: String,
                         mimeType: String,
                         textEncoding: String,
                         baseURL: String,
                         unreachableURL: String?,
                         replace: Bool) {
      var unreachPtr: UnsafePointer<Int8>? 

      if let uurl = unreachableURL {
        unreachPtr = uurl.withCString { (ubuf: UnsafePointer<Int8>?) -> UnsafePointer<Int8>? in
          return ubuf
        }
      }

      string.withCString { databuf in
        mimeType.withCString { mimebuf in
          textEncoding.withCString { textbuf in
              baseURL.withCString { basebuf in
                _WebLocalFrameLoadData(reference, databuf, string.count, mimebuf, textbuf, basebuf, unreachPtr ?? nil, replace ? 1 : 0)
              }
          }
        }
      }
    }

    public func loadHTMLString(html: WebData,
                               baseURL: String,
                               unreachableURL: String?,
                               replace: Bool) {
      //print("WebLocalFrame.loadHTMLString begin")
       
      var unreachPtr: UnsafePointer<Int8>? 

      if let uurl = unreachableURL {
        unreachPtr = uurl.withCString { (ubuf: UnsafePointer<Int8>?) -> UnsafePointer<Int8>? in
          return ubuf
        }
      }
      baseURL.withCString { basebuf in
        let databuf = html.data!.bindMemory(to: Int8.self, capacity: html.size)
        _WebLocalFrameLoadHTMLString(reference, databuf, html.size, basebuf, unreachPtr ?? nil, replace ? 1 : 0)
      }
      
      //print("WebLocalFrame.loadHTMLString end")
    }

    public func stopLoading() {
      _WebLocalFrameStopLoading(reference)
    }

    public func setReferrerForRequest(request: WebURLRequest, url: String) {
      url.withCString { urlbuf in
        _WebLocalFrameSetReferrerForRequest(reference, request.reference, urlbuf)
      }
    }

    // NOTE: commented for now, giving WebURLLoader now is a protocol
    //       we need to figure it out, the best way to return the URLLoader
    //       from this method now

    // public func createAssociatedURLLoader(options: WebURLLoaderOptions) -> WebURLLoader {
    //   let ref = _WebLocalFrameCreateAssociatedURLLoader(reference,
    //       Int32(options.untrustedHTTP ? 1 : 0), 
    //       Int32(options.exposeAllResponseHeaders ? 1 : 0),
    //       WebPreflightPolicyEnum(rawValue: UInt32(options.preflightPolicy.rawValue)))//,
       
    //   return WebURLLoaderImpl(reference: ref!)
    // }

    public func replaceSelection(text: String) {
      text.withCString { textbuf in 
          _WebLocalFrameReplaceSelection(reference, textbuf)
      }
    }

    public func setMarkedText(text: String, location: Int, length: Int) {
      text.withCString { textbuf in
          _WebLocalFrameSetMarkedText(reference, textbuf, UInt32(location), UInt32(length))
      }
    }
    
    public func unmarkText() {
      _WebLocalFrameUnmarkText(reference)
    }

    public func commitNavigation(
      request: WebURLRequest,
      loadType: WebFrameLoadType,
      item: WebHistoryItem?,
      isClientRedirect: Bool) {
        _WebLocalFrameCommitNavigation(
          reference,
          request.reference,
          CInt(loadType.rawValue),
          item != nil ? item!.reference : nil,
          isClientRedirect ? 1 : 0) 
    }

    public func commitSameDocumentNavigation(
      url: String, 
      loadType: WebFrameLoadType,
      item: WebHistoryItem?,
      isClientRedirect: Bool) -> CommitResult {
      let result = url.withCString { (str) -> CommitResult in
       return CommitResult(
        rawValue: Int(_WebLocalFrameCommitSameDocumentNavigation(
         reference,
         str,
         CInt(loadType.rawValue),
         item != nil ? item!.reference : nil,
         isClientRedirect ? 1 : 0)))!
      }
      return result
    }

    public func firstRectForCharacterRange(location: Int, length: Int, rect: inout IntRect) -> Bool {
      var x: Int32 = 0, y: Int32 = 0, width: Int32 = 0, height: Int32 = 0
      let result = _WebLocalFrameFirstRectForCharacterRange(reference, UInt32(location), UInt32(length), &x, &y, &width, &height) == 0 ? false : true
      rect.x = Int(x)
      rect.y = Int(y)
      rect.width = Int(width)
      rect.height = Int(height)
      return result
    }

    public func characterIndexForPoint(point: IntPoint) -> Int {
      return Int(_WebLocalFrameCharacterIndexForPoint(reference, Int32(point.x), Int32(point.y)))
    }

    public func executeCommand(command: String) -> Bool {
      let result = command.withCString { strbuf -> Bool in
          return _WebLocalFrameExecuteCommand(reference, strbuf) == 0 ? false : true
      }
      return result
    }

    public func executeCommand(command: String, value: String) -> Bool {
      let result = command.withCString { cmdbuf -> Bool in
          return value.withCString { valbuf -> Bool in
              return _WebLocalFrameExecuteCommandValue(reference, cmdbuf, valbuf) == 0 ? false : true
          }
      }
      return result
    }
    
    public func isCommandEnabled(command: String) -> Bool {
      let result = command.withCString { strbuf -> Bool in    
          return _WebLocalFrameIsCommandEnabled(reference, strbuf) == 0 ? false : true
      }
      return result
    }
    
    public func replaceMisspelledRange(text: String) {
      text.withCString { strbuf in
          _WebLocalFrameReplaceMisspelledRange(reference, strbuf)
      }
    }
    
    public func removeSpellingMarkers() {
      _WebLocalFrameRemoveSpellingMarkers(reference)
    }

    public func selectionAsText() -> String {
      var len: CInt = 0
      let cstr = _WebLocalFrameSelectionAsText(reference, &len)
      return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
    }
    
    public func selectionAsMarkup() -> String {
      var len: CInt = 0
      let cstr = _WebLocalFrameSelectionAsMarkup(reference, &len)
      return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
    }

    public func selectWordAroundCaret() -> Bool {
      return _WebLocalFrameSelectWordAroundCaret(reference) == 0 ? false : true
    }

    public func selectRange(base: IntPoint, extent: IntPoint) {
      _WebLocalFrameSelectRangeInt(reference, Int32(base.x), Int32(base.y), Int32(extent.x), Int32(extent.y))
    }

    public func selectRange(range: TextRange, hide: Bool) {
      _WebLocalFrameSelectRange(reference, CInt(range.start), CInt(range.end), hide ? 1 : 0)
    }

    public func moveRangeSelection(base: IntPoint, extent: IntPoint, granularity: TextGranularity = .Character) {
      _WebLocalFrameMoveRangeSelection(reference, Int32(base.x), Int32(base.y), Int32(extent.x), Int32(extent.y), WebTextGranularityEnum(rawValue: UInt32(granularity.rawValue)))
    }
    
    public func moveCaretSelection(point: IntPoint) {
      _WebLocalFrameMoveCaretSelection(reference, Int32(point.x), Int32(point.y))
    }

    public func setEditableSelectionOffsets(start: Int, end: Int) -> Bool {
      return _WebLocalFrameSetEditableSelectionOffsets(reference, Int32(start), Int32(end)) == 0 ? false : true
    }
    
    public func setCompositionFromExistingText(compositionStart: Int, compositionEnd: Int, spans: [WebImeTextSpan]) -> Bool {
      var type = ContiguousArray<CInt>()
      var start = ContiguousArray<CInt>()
      var end = ContiguousArray<CInt>()
      var thick = ContiguousArray<CInt>()
      var ucolor = ContiguousArray<CInt>()
      var bg = ContiguousArray<CInt>()

      for span in spans {
        type.append(CInt(span.type.rawValue))
        start.append(CInt(span.startOffset))
        end.append(CInt(span.endOffset))
        ucolor.append(CInt(span.underlineColor.value))
        bg.append(CInt(span.backgroundColor.value))
        thick.append(CInt(span.thickness.rawValue))
      }

      var typePtr: UnsafeMutableBufferPointer<CInt>?
      var startPtr: UnsafeMutableBufferPointer<CInt>?
      var endPtr: UnsafeMutableBufferPointer<CInt>?
      var ucolorPtr: UnsafeMutableBufferPointer<CInt>?
      var thickPtr: UnsafeMutableBufferPointer<CInt>?
      var bgPtr: UnsafeMutableBufferPointer<CInt>?

      type.withUnsafeMutableBufferPointer { typePtr = $0}
      start.withUnsafeMutableBufferPointer { startPtr = $0}
      end.withUnsafeMutableBufferPointer { endPtr = $0 }
      ucolor.withUnsafeMutableBufferPointer { ucolorPtr = $0 }
      thick.withUnsafeMutableBufferPointer { thickPtr = $0 }
      bg.withUnsafeMutableBufferPointer { bgPtr = $0 }
                          
      return _WebLocalFrameSetCompositionFromExistingText(reference, Int32(compositionStart), Int32(compositionEnd), typePtr!.baseAddress, startPtr!.baseAddress, endPtr!.baseAddress, ucolorPtr!.baseAddress, thickPtr!.baseAddress, bgPtr!.baseAddress, Int32(spans.count)) == 0 ? false : true
    }
    
    public func extendSelectionAndDelete(before: Int, after: Int) {
      _WebLocalFrameExtendSelectionAndDelete(reference, Int32(before), Int32(after))
    }

      public func printBegin(params: WebPrintParams, constrainToNode: WebNode?) -> Int {
        return Int(_WebLocalFramePrintBegin(
          reference,
          Int32(params.printContentArea.x), 
          Int32(params.printContentArea.y), 
          Int32(params.printContentArea.width), 
          Int32(params.printContentArea.height),
          Int32(params.printableArea.x),
          Int32(params.printableArea.y),
          Int32(params.printableArea.width),
          Int32(params.printableArea.height),
          Int32(params.paperSize.width),
          Int32(params.paperSize.height),
          Int32(params.printerDPI),
          params.rasterizePdf ? 1 : 0,
          WebPrintScalingOptionEnum(rawValue: UInt32(params.printScalingOption.rawValue)),
          params.usePrintLayout ? 1 : 0,
          constrainToNode != nil ? constrainToNode!.reference : nil))
      }

      public func getPrintPageShrink(page: Int) -> Float {
        return _WebLocalFrameGetPrintPageShrink(reference, Int32(page))
      }

      public func printPage(pageToPrint: Int, canvas: Canvas) -> Float {
        return _WebLocalFramePrintPage(reference, Int32(pageToPrint), canvas.nativeCanvas.reference)
      }

      public func printEnd() {
        _WebLocalFramePrintEnd(reference)
      }

      public func isPrintScalingDisabledForPlugin(node: WebNode?) -> Bool {
        return _WebLocalFrameIsPrintScalingDisabledForPlugin(reference, node != nil ? node!.reference : nil) == 0 ? false : true
      }

      public func isPageBoxVisible(pageIndex: Int) -> Bool {
        return _WebLocalFrameIsPageBoxVisible(reference, Int32(pageIndex)) == 0 ? false : true
      }

      public func hasCustomPageSizeStyle(pageIndex: Int) -> Bool {
        return _WebLocalFrameHasCustomPageSizeStyle(reference, Int32(pageIndex)) == 0 ? false : true
      }

      public func pageSizeAndMarginsInPixels(pageIndex: Int,
       pageSize: IntSize,
       marginTop: inout Int,
       marginRight: inout Int,
       marginBottom: inout Int,
       marginLeft: inout Int) {

        var top: Int32 = 0, left: Int32 = 0, right: Int32 = 0, bottom: Int32 = 0

        _WebLocalFramePageSizeAndMarginsInPixels(reference, 
          Int32(pageIndex), 
          Int32(pageSize.width), 
          Int32(pageSize.height),
          &top,
          &right,
          &bottom,
          &left)

        marginTop = Int(top)
        marginRight = Int(right)
        marginBottom = Int(bottom)
        marginLeft = Int(left)
      }

      public func pageProperty(propertyName: String, pageIndex: Int) -> String {
        return propertyName.withCString { namebuf -> String in
          var len: CInt = 0
          let cstr = _WebLocalFramePageProperty(reference, namebuf, Int32(pageIndex), &len)
          return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
        }
      }

      public func find(identifier: Int,
       searchText: String,
       options: WebFindOptions,
       wrapWithinFrame: Bool,
       selection: inout IntRect) -> Bool {

       var x: Float = 0, y: Float = 0, w: Float = 0, h: Float = 0

       let result = searchText.withCString { searchstr -> Bool in

        return _WebLocalFrameFind(reference, 
          Int32(identifier),
          searchstr,
          options.forward ? 1 : 0,
          options.matchCase ? 1 : 0,
          options.findNext ? 1 : 0,
          options.wordStart ? 1 : 0,
          options.medialCapitalAsWordStart ? 1 : 0, 
          wrapWithinFrame ? 1 : 0,
          &x,
          &y,
          &w,
          &h) == 0 ? false : true
      }

      selection.x = Int(x)
      selection.y = Int(y)
      selection.width = Int(w)
      selection.height = Int(h)

      return result
    }

    public func requestFind(requestId: Int32, searchText: String, options: WebFindOptions) {

      _WebLocalFrameRequestFind(
        reference, 
        requestId, 
        searchText._guts.startUTF16,
        options.forward ? 1 : 0,
        options.matchCase ? 1 : 0,
        options.findNext ? 1 : 0,
        options.wordStart ? 1 : 0,
        options.medialCapitalAsWordStart ? 1 : 0,
        options.force ? 1 : 0)

    }

    public func stopFinding(action: WebFrameStopFindAction) {
      _WebLocalFrameStopFinding(reference, CInt(action.rawValue))
    }

    public func clearActiveFindMatch() {
      _WebLocalFrameClearActiveFindMatch(reference)
    }

    public func findMatchMarkersVersion() -> Int {
      return Int(_WebLocalFrameFindMatchMarkersVersion(reference))
    }

    public func activeFindMatchRect() -> FloatRect {
      var x: Float = 0, y: Float = 0, width: Float = 0, height: Float = 0
      _WebLocalFrameActiveFindMatchRect(reference, &x, &y, &width, &height)
      return FloatRect(x: x, y: y, width: width, height: height)
    }

    public func findMatchRects() -> [FloatRect] {
      let maxRects = 1000
      var x: [Float] = []
      var y: [Float] = []
      var w: [Float] = []
      var h: [Float] = []
      var count: Int32 = 0
      var result: [FloatRect] = []

      x.reserveCapacity(maxRects)
      y.reserveCapacity(maxRects)
      w.reserveCapacity(maxRects)
      h.reserveCapacity(maxRects)

      var xOffset = x.withUnsafeMutableBufferPointer { xbuf -> UnsafeMutablePointer<Float>? in
        return xbuf.baseAddress
      }

      var yOffset = y.withUnsafeMutableBufferPointer { ybuf -> UnsafeMutablePointer<Float>? in
        return ybuf.baseAddress
      }

      var wOffset = w.withUnsafeMutableBufferPointer { wbuf -> UnsafeMutablePointer<Float>? in
        return wbuf.baseAddress
      }

      var hOffset = h.withUnsafeMutableBufferPointer { hbuf -> UnsafeMutablePointer<Float>? in
        return hbuf.baseAddress
      }

      _WebLocalFrameFindMatchRects(reference, &xOffset, &yOffset, &wOffset, &hOffset, &count)

      for i in 0...Int(count) {
        result.append(FloatRect(x: x[i], y: y[i], width: w[i], height: h[i]))
      }

      return result
    }

    public func selectNearestFindMatch(point: FloatPoint,
     selection: inout IntRect) -> Int {

      var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0

      let result = Int(_WebLocalFrameSelectNearestFindMatch(reference, Int32(point.x), Int32(point.y), &x, &y, &w, &h))

      selection.x = Int(x)
      selection.y = Int(y)
      selection.width = Int(w)
      selection.height = Int(h)

      return result
    }

    public func setTickmarks(rects: [IntRect]) {
      var x: [Int32] = []
      var y: [Int32] = []
      var w: [Int32] = []
      var h: [Int32] = []

      for (i, rect) in rects.enumerated() {
        x[i] = Int32(rect.x)
        y[i] = Int32(rect.y)
        w[i] = Int32(rect.width)
        h[i] = Int32(rect.height)
      }

      x.withUnsafeMutableBufferPointer { xbuf in
       y.withUnsafeMutableBufferPointer { ybuf in
        w.withUnsafeMutableBufferPointer { wbuf in
         h.withUnsafeMutableBufferPointer { hbuf in
          _WebLocalFrameSetTickmarks(reference, xbuf.baseAddress, ybuf.baseAddress, wbuf.baseAddress, hbuf.baseAddress, Int32(rects.count))
        }
      }
    }
  }
  }

  public func dispatchMessageEventWithOriginCheck(
    intendedTargetOrigin: WebSecurityOrigin,
    event: WebInputEvent,
    hasUserGesture: Bool) {
    _WebLocalFrameDispatchMessageEventWithOriginCheck(reference, intendedTargetOrigin.reference, event.reference, hasUserGesture ? 1 : 0)
  }

  public func setFrameOwnerProperties(properties: WebFrameOwnerProperties) {
    _WebLocalFrameSetFrameOwnerProperties(reference,
      WebScrollingModeEnum(rawValue: UInt32(properties.scrollingMode.rawValue)), 
      Int32(properties.marginWidth),
      Int32(properties.marginHeight))
  }

  public func requestFromHistoryItem(item: WebHistoryItem, policy: WebURLRequest.CachePolicy) -> WebURLRequest {
    let ref = _WebLocalFrameRequestFromHistoryItem(reference, item.reference, WebURLRequestCachePolicyEnum(rawValue: UInt32(policy.rawValue)))
    return WebURLRequest(reference: ref!, owned: true)
  }

  public func requestForReload(type: WebFrameLoadType, overrideURL: String) -> WebURLRequest {
    let ref = overrideURL.withCString { urlbuf -> WebURLRequestRef in
      return _WebLocalFrameRequestForReload(reference, WebFrameLoadEnum(rawValue: UInt32(type.rawValue)), urlbuf)
    }
    return WebURLRequest(reference: ref, owned: true)
  }

  public func load(request: WebURLRequest, 
   type: WebFrameLoadType,
   item: WebHistoryItem,
   historyType: WebHistoryLoadType,
   isClientRedirect: Bool) {

    _WebLocalFrameLoad(reference, request.reference, WebFrameLoadEnum(rawValue: UInt32(type.rawValue)), item.reference, WebHistoryLoadTypeEnum(rawValue: UInt32(historyType.rawValue)), isClientRedirect ? 1 : 0)
  }

  public func setCommittedFirstRealLoad() {
    _WebLocalFrameSetCommittedFirstRealLoad(reference)
  }

  public func sendOrientationChangeEvent() {
    _WebLocalFrameSendOrientationChangeEvent(reference)
  }

  public func getPrintPresetOptionsForPlugin(node: WebNode, options: inout WebPrintPresetOptions) -> Bool {

    let maxpages = 1000

    var isScalingDisabled: Int32 = 0
    var copies: Int32 = 0
    var duplexMode: WebDuplexModeEnum = WebUnknownDuplexMode
    var pageRangeFrom: [Int32] = []
    var pageRangeTo: [Int32] = []
    var pageRangeLenght: Int32 = 0
    var isPageSizeUniform: Int32 = 0
    var uniformPageSizeWidth: Int32 = 0
    var uniformPageSizeHeight: Int32 = 0

    pageRangeFrom.reserveCapacity(maxpages)
    pageRangeTo.reserveCapacity(maxpages)

    var fromAddress = pageRangeFrom.withUnsafeMutableBufferPointer { (from: inout UnsafeMutableBufferPointer<Int32>) -> UnsafeMutablePointer<Int32>? in
      return from.baseAddress
    }

    var toAddress = pageRangeTo.withUnsafeMutableBufferPointer { (to: inout UnsafeMutableBufferPointer<Int32>) -> UnsafeMutablePointer<Int32>? in
      return to.baseAddress
    }

    let result = _WebLocalFrameGetPrintPresetOptionsForPlugin(
      reference,
      node.reference,
      &isScalingDisabled,
      &copies,
      &duplexMode,
      &fromAddress,
      &toAddress,
      &pageRangeLenght,
      &isPageSizeUniform,
      &uniformPageSizeWidth,
      &uniformPageSizeHeight) == 0 ? false : true

    options.pageRanges.reserveCapacity(Int(pageRangeLenght))

    for i in 0...Int(pageRangeLenght) {
      let range = WebPageRange(from: Int(pageRangeFrom[i]), to: Int(pageRangeTo[i]))
      options.pageRanges.insert(range, at: i)            
    }

    options.isScalingDisabled = isScalingDisabled == 0 ? false : true
    options.copies = Int(copies)
    options.duplexMode = WebDuplexMode(rawValue: Int(duplexMode.rawValue))!
    options.isPageSizeUniform = isPageSizeUniform == 0 ? false : true
    options.uniformPageSize.width = Int(uniformPageSizeWidth)
    options.uniformPageSize.height = Int(uniformPageSizeHeight)

    return result
  }

  public func requestExecuteScriptAndReturnValue(
    source: String,
    userGesture: Bool, 
    callback: WebScriptExecutionCallback) {

    source.withCString { sourcebuf in 
      _WebLocalFrameRequestExecuteScriptAndReturnValue(reference, sourcebuf, userGesture ? 1 : 0, nil)//callback.reference)
    }
  }

  public func requestExecuteScriptInIsolatedWorld(
    worldId: Int, 
    sources: [String], 
    userGesture: Bool,
    executionType: WebScriptExecutionType,
    callback: WebScriptExecutionCallback) {

    var csources: [UnsafePointer<CChar>?] = []
    csources.reserveCapacity(sources.count)

    for source in sources {
      source.withCString { cstr in
        csources.append(cstr)
      }
    }

    let sourcesCount = UInt32(csources.count)

    csources.withUnsafeMutableBufferPointer { sourcebuf in 
      _WebLocalFrameRequestExecuteScriptInIsolatedWorld(reference, 
        Int32(worldId), 
        sourcebuf.baseAddress, 
        sourcesCount, 
        userGesture ? 1 : 0, 
        WebScriptExecutionTypeEnum(UInt32(executionType.rawValue)), 
        nil)//callback.reference)
    }
  }

  public func requestRunTask(task: WebSuspendableTask) {
    assert(false)
    //_WebLocalFrameRequestRunTask(reference, task.reference)
  }

  public func setIsolatedWorldHumanReadableName(worldId: Int, string: String) {
    string.withCString { strbuf in
      _WebLocalFrameSetIsolatedWorldHumanReadableName(reference, Int32(worldId), strbuf)
    }
  }

  public func moveRangeSelectionExtent(point: IntPoint) {
    _WebLocalFrameMoveRangeSelectionExtent(reference, Int32(point.x), Int32(point.y))
  }

  public func setContentSettingsClient(client: WebContentSettingsClient) {
    assert(false)
    // TODO: To make this right we will need to bind the callbacks
    // on the c++ side to the swift protocol impl equivalent        
    // _WebLocalFrameSetContentSettingsClient(reference, client)
  }

  public func reloadImage(node: WebNode) {
    _WebLocalFrameReloadImage(reference, node.reference)
  }

  public func didCallAddSearchProvider() {
    _WebLocalFrameDidCallAddSearchProvider(reference)
  }

  public func didCallIsSearchProviderInstalled() {
    _WebLocalFrameDidCallIsSearchProviderInstalled(reference)
  }

  public func notifyUserActivation() {
    _WebLocalFrameNotifyUserActivation(reference)
  }

  public func advanceFocusInForm(type: WebFocusType) {
    _WebLocalFrameAdvanceFocusInForm(reference, CInt(type.rawValue))   
  }

  public func copyImage(at: IntPoint) {
    _WebLocalFrameCopyImageAt(reference, CInt(at.x), CInt(at.y))
  }

  public func saveImage(at: IntPoint) {
    _WebLocalFrameSaveImageAt(reference, CInt(at.x), CInt(at.y))   
  }

  public func clientDroppedNavigation() {
    _WebLocalFrameClientDroppedNavigation(reference)
  }

  public func collapse(collapsed: Bool) {
    _WebLocalFrameCollapse(reference, collapsed ? 1 : 0)
  }

  public func checkCompleted() {
    _WebLocalFrameCheckCompleted(reference)
  }

  public func getSurroundingText(maxLength: UInt32) -> WebSurroundingText {
    return WebSurroundingText(frame: self, maxLength: maxLength)
  }

  public func selectionTextDirection(start: inout TextDirection, end: inout TextDirection) -> Bool {
    var ds: CInt = CInt(start.rawValue)
    var de: CInt = CInt(end.rawValue)
    let r = _WebLocalFrameSelectionTextDirection(reference, &ds, &de)
    if r != 0 {
      start = TextDirection(rawValue: Int(ds))!
      end = TextDirection(rawValue: Int(de))!
    }      
    return r != 0
  }

  public func setTextDirection(_ direction: TextDirection) {
    _WebLocalFrameSetTextDirection(reference, CInt(direction.rawValue))
  }

}

fileprivate func createMainFrameNative(state: UnsafeMutableRawPointer?, view: WebView, callbacks: WebFrameClientCbs, interfaceRegistry: WebInterfaceRegistry?) -> WebFrameRef {
  return _WebLocalFrameCreateMainFrame(state, view.reference, callbacks, interfaceRegistry != nil ? interfaceRegistry!.reference : nil)
}

fileprivate func createCallbacks(client: WebLocalFrameClient) -> WebFrameClientCbs {
    var callbacks = WebFrameClientCbs()
    memset(&callbacks, 0, MemoryLayout<WebFrameClientCbs>.stride)

    callbacks.bindToFrame = { (handle: UnsafeMutableRawPointer?,
                               frame: UnsafeMutableRawPointer?) in
      let localFrame = unsafeBitCast(handle, to: WebLocalFrame.self)
      //let frameToBind = WebLocalFrame(reference: frame!)
      //print("WebLocalFrame.bindToFrame: owner frame: \(localFrame.reference) given frame: \(frame)")
      if let client = localFrame.client {
        //frameToBind.client = client
        localFrame.reference = frame!
        client.bindToFrame(frame: localFrame)//frameToBind)
      }
    }
    
    // -> WebBlameContextRef
    callbacks.frameBlameContext = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
      //let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      //if let client = frame.client {
      //}
      return nil
    }

    callbacks.didEnforceInsecureRequestPolicy = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didEnforceInsecureRequestPolicy()
      }
    }

    // we dont actually need to implement this, but just in case
    callbacks.interfaceProvider = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
      return nil
    }
    callbacks.remoteNavigationAssociatedInterfaces = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
      return nil
    }

    callbacks.didEnforceInsecureNavigationsSet = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didEnforceInsecureNavigationsSet()
      } 
    }

    callbacks.didCreateDocumentLoader = { (handle: UnsafeMutableRawPointer?, loader: UnsafeMutableRawPointer?) in 
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        frame._documentLoader = WebDocumentLoader(reference: loader!)
        client.didCreateDocumentLoader(loader: frame._documentLoader!)
      } 
    }

    callbacks.createPlugin = { (handle: UnsafeMutableRawPointer?, 
                                url: UnsafePointer<CChar>?,
                                mimeType: UnsafePointer<CChar>?,
                                attributeNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?,
                                attributeNamesLen: Int32,
                                attributeValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?,
                                attributeValuesLen: Int32,
                                loadManually: Int32) -> WebPluginRef? in
        
      return nil
    }

    callbacks.createMediaPlayer = { (
        handle: UnsafeMutableRawPointer?, 
        url: UnsafePointer<CChar>?, 
        client: WebMediaPlayerClientRef?, 
        eclient: WebMediaPlayerEncryptedMediaClientRef?, 
        module: WebContentDecryptionModuleRef?, 
        sinkId: UnsafePointer<CChar>?,
        tree: WebLayerTreeViewRef?) -> WebMediaPlayerRef? in

        guard handle != nil else {
            return nil
        }
        
        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
        
        //let webLayerTreeView = unsafeBitCast(tree, to: WebLayerTreeView.self)

        if let player = frame.client?.createMediaPlayer(
                url: String(cString: url!), 
                client: WebMediaPlayerClient(reference: client!), 
                encryptedClient: eclient != nil ? WebMediaPlayerEncryptedMediaClient(reference: eclient!) : nil, 
                module: module != nil ? WebContentDecryptionModule(reference: module!) : nil, 
                sinkId: sinkId == nil ? String() : String(cString: sinkId!)) {

          return player.reference     
        }

        return nil
    }

    callbacks.createMediaPlayerStream = { (
        handle: UnsafeMutableRawPointer?, 
        descriptor: WebMediaStreamDescriptorRef?, 
        client: WebMediaPlayerClientRef?, 
        eclient: WebMediaPlayerEncryptedMediaClientRef?, 
        module: WebContentDecryptionModuleRef?, 
        sinkId: UnsafePointer<CChar>?,
        tree: WebLayerTreeViewRef?) -> WebMediaPlayerRef? in

        guard handle != nil else {
            return nil
        }
        
        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
        
        //let webLayerTreeView = unsafeBitCast(tree, to: WebLayerTreeView.self)

        if let player = frame.client?.createMediaPlayer(
                descriptor: MediaStreamDescriptor(reference: descriptor!), 
                client: WebMediaPlayerClient(reference: client!), 
                encryptedClient: eclient != nil ? WebMediaPlayerEncryptedMediaClient(reference: eclient!) : nil, 
                module: module != nil ? WebContentDecryptionModule(reference: module!) : nil, 
                sinkId: sinkId == nil ? String() : String(cString: sinkId!)) {

          return player.reference     
        }

        return nil
    }

    callbacks.createMediaSession = { (handle: UnsafeMutableRawPointer?) -> WebMediaSessionRef? in 
        
        guard handle != nil else {
            return nil
        }
        
        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
        
        if let session = frame.client?.createMediaSession() {
            return session.reference
        }

        return nil
    }
    
    callbacks.createApplicationCacheHost = { (handle: UnsafeMutableRawPointer?, 
        client: WebApplicationCacheHostClientRef?) -> WebApplicationCacheHostRef? in 
        
        guard handle != nil else {
            return nil
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        var cacheHost: WebApplicationCacheHostClient? = nil

        if let clientRef = client {
            cacheHost = WebApplicationCacheHostClient(reference: clientRef)  
        }

        if let appCacheHost = frame.client?.createApplicationCacheHost(
            frame: frame, 
            client: cacheHost) {
            return appCacheHost.reference
        }
        
        return nil
    
    }

    callbacks.createServiceWorkerProvider = { (
        handle: UnsafeMutableRawPointer?) -> WebServiceWorkerProviderRef? in
        
        
        guard handle != nil else {
            return nil
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
        
        if let serviceWorkerProvider = frame.client?.createServiceWorkerProvider(
            frame: frame) {
            return serviceWorkerProvider.reference
        }
        
        return nil
    }

    callbacks.createExternalPopupMenu = { (handle: UnsafeMutableRawPointer?,
        itemHeight: Int32,
        itemFontSize: Int32,
        selectedIndex: Int32,
        rightAligned: Int32,
        allowMultipleSelection: Int32, 
        client: WebExternalPopupMenuClientRef?) -> WebExternalPopupMenuRef? in 
        
        guard handle != nil else {
            return nil
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
        var popupMenuClient: WebExternalPopupMenuClient? = nil

        if client != nil {
            popupMenuClient = WebExternalPopupMenuClient(reference: client!)
        }

        var info = WebPopupMenuInfo()
        info.itemHeight = Int(itemHeight) 
        info.itemFontSize = Int(itemFontSize)
        info.selectedIndex = Int(selectedIndex) 
        info.rightAligned = rightAligned == 0 ? false: true
        info.allowMultipleSelection = allowMultipleSelection == 0 ? false : true

        if let popupMenu = frame.client?.createExternalPopupMenu(info: info, client: popupMenuClient) {
            return popupMenu.reference
        }

        return nil
    }

    callbacks.getCurrentLocalFrame = { (handle: UnsafeMutableRawPointer?) -> WebFrameRef? in 
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      return frame.reference
    }

    callbacks.getRoutingId = { (handle: UnsafeMutableRawPointer?) -> CInt in 
      print("WebLocalFrame.getRoutingId")
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      return CInt(frame.client?.routingId ?? 0)
    }

    callbacks.cookieJar = { (handle: UnsafeMutableRawPointer?) -> WebCookieJarRef? in 
        
        guard handle != nil else {
            return nil
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let cookieJar = frame.client?.cookieJar(frame: frame) {
            return cookieJar.reference
        }

        return nil
    }

    callbacks.canCreatePluginWithoutRenderer = { (handle: UnsafeMutableRawPointer?, mimeType: UnsafePointer<CChar>?) -> Int32 in 
        
        guard handle != nil else {
            return 0
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let canCreate = frame.client?.canCreatePluginWithoutRenderer(mimeType: String(cString: mimeType!)) {
            return canCreate ? 1 : 0
        }

        return 0
    }

    callbacks.didAccessInitialDocument = { (handle: UnsafeMutableRawPointer?) in//, targetFrame: WebFrameRef?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didAccessInitialDocument(frame: frame)
        }

    }

    callbacks.createChildFrame = { (
        handle: UnsafeMutableRawPointer?,
        parent: WebFrameRef?, 
        type: WebTreeScopeEnum, 
        frameName: UnsafePointer<CChar>?, 
        fallbackName: UnsafePointer<CChar>?, 
        sandboxFlags: WebSandboxFlagsEnum, 
        scrollingMode: WebScrollingModeEnum, 
        marginWidth: CInt, 
        marginHeight: CInt,
        allowFullscreen: CInt,
        allowPaymentRequest: CInt,
        isDisplayNone: CInt) -> WebFrameRef? in

        guard handle != nil else {
            return nil
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
        
        var properties = WebFrameOwnerProperties()
        properties.scrollingMode = WebFrameOwnerProperties.ScrollingMode(rawValue: Int(scrollingMode.rawValue))! 
        properties.marginWidth = Int(marginWidth)
        properties.marginHeight = Int(marginHeight)
        properties.allowFullscreen = allowFullscreen != 0
        properties.allowPaymentRequest = allowPaymentRequest != 0
        properties.isDisplayNone = isDisplayNone != 0

        if let childFrame = frame.client?.createChildFrame(
            parent: WebFrame(reference: parent!), 
            type: WebTreeScopeType(rawValue: Int(type.rawValue))!, 
            name: String(cString: frameName!),
            flags: WebSandboxFlags(rawValue: Int(sandboxFlags.rawValue)), 
            properties: properties) {
            
            return childFrame.reference
        }

        return nil
    }

    callbacks.didChangeOpener = { (handle: UnsafeMutableRawPointer?, targetFrame: WebFrameRef?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didChangeOpener(opener: targetFrame != nil ? WebFrame(reference: targetFrame!) : nil)
        }

    }

    callbacks.findFrame = { (handle: UnsafeMutableRawPointer?, frameName: UnsafePointer<CChar>?) -> UnsafeMutableRawPointer? in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

      if let client = frame.client {
        if let found = client.findFrame(name: String(cString: frameName!)) {
          return found.reference
        }
      }
      return nil     
    }

    callbacks.frameDetached = { (handle: UnsafeMutableRawPointer?, 
        type: WebDetachEnum) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
        if let client = frame.client {
          client.frameDetached(
            type: WebFrameDetachType(rawValue: Int(type.rawValue))!)
        }
    }

    callbacks.didChangeFramePolicy = { (handle: UnsafeMutableRawPointer?, childFrame: UnsafeMutableRawPointer?, flags: WebSandboxFlagsEnum) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didChangeFramePolicy(childFrame: childFrame != nil ? WebFrame(reference: childFrame!) : nil, flags: Int(flags.rawValue))
      }
    }

    callbacks.didSetFramePolicyHeaders = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didSetFramePolicyHeaders()
      }
    }

    callbacks.didAddContentSecurityPolicies = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didAddContentSecurityPolicies()
      } 
    }

    callbacks.frameFocused = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.frameFocused()
        }

    }

    callbacks.didChangeName = { (handle: UnsafeMutableRawPointer?, 
        name: UnsafePointer<CChar>?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
          client.didChangeName(name: String(cString: name!))
        }

    }

    callbacks.willCommitProvisionalLoad = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
          client.willCommitProvisionalLoad()
        }      
    }

    callbacks.didChangeFrameOwnerProperties = { (handle: UnsafeMutableRawPointer?, 
            childFrame: WebFrameRef?, 
            scrollingMode: WebScrollingModeEnum, 
            marginWidth: Int32, 
            marginHeight: Int32) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            
            var properties = WebFrameOwnerProperties()
            properties.scrollingMode = WebFrameOwnerProperties.ScrollingMode(rawValue: Int(scrollingMode.rawValue))!
            properties.marginWidth = Int(marginWidth)
            properties.marginHeight = Int(marginHeight)

            client.didChangeFrameOwnerProperties(child: WebFrame(reference: childFrame!), 
                properties: properties)
        }
    }

    callbacks.didMatchCSS = { (handle: UnsafeMutableRawPointer?, 
        newlyMatchingSelectors: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
        newlyMatchingSelectorsLen: Int32, 
        stoppedMatchingSelectors: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
        stoppedMatchingSelectorsLen: Int32) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            var newSelectors: [String] = []
            var stoppedSelectors: [String] = []

            for i in 0...Int(newlyMatchingSelectorsLen) {
                newSelectors.insert(String(cString: newlyMatchingSelectors![i]!), at: i)
            }

            for i in 0...Int(stoppedMatchingSelectorsLen) {
                stoppedSelectors.insert(String(cString: stoppedMatchingSelectors![i]!), at: i)
            }

            client.didMatchCSS(
                frame: frame,//WebFrame(reference: targetFrame!), 
                newlyMatchingSelectors: newSelectors, 
                stoppedMatchingSelectors: stoppedSelectors)
        }
    }
    callbacks.setHasReceivedUserGesture = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.setHasReceivedUserGesture()
      }      
    }

    callbacks.setHasReceivedUserGestureBeforeNavigation = { (handle: UnsafeMutableRawPointer?, value: CInt) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.setHasReceivedUserGestureBeforeNavigation(value != 0)
      } 
    }

    callbacks.shouldReportDetailedMessageForSource = { (handle: UnsafeMutableRawPointer?, 
        source: UnsafePointer<CChar>?) -> Int32  in 
        
        guard handle != nil else {
            return 0
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            return client.shouldReportDetailedMessageForSource(source: String(cString: source!)) ? 1 : 0
        }

        return 0
    }

    callbacks.didAddMessageToConsole = { (
            handle: UnsafeMutableRawPointer?,
            messageLevel: WebConsoleMessageLevelEnum, 
            messageText: UnsafePointer<CChar>?, 
            sourceName: UnsafePointer<CChar>?, 
            sourceLine: UInt32, 
            stackTrace: UnsafePointer<CChar>?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {

            let message = WebConsoleMessage(
                level: WebConsoleMessage.Level(rawValue: Int(messageLevel.rawValue))!, 
                text: String(cString: messageText!))

            client.didAddMessageToConsole(
                message: message,
                sourceName: String(cString: sourceName!), 
                sourceLine: Int(sourceLine), 
                stackTrace: String(cString: stackTrace!))
        }
    }

    callbacks.downloadURL = { (handle: UnsafeMutableRawPointer?, urlRequest: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.downloadURL(urlRequest: WebURLRequest(reference: urlRequest!))
      }
    }

    callbacks.loadErrorPage = { (handle: UnsafeMutableRawPointer?, reason: CInt) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.loadErrorPage(reason: Int(reason))
      }
    }

    callbacks.decidePolicyForNavigation = { (handle: UnsafeMutableRawPointer?,
        extraData: WebDataSourceExtraDataRef?,
        urlRequest: WebURLRequestRef?,
        navigationType: WebNavigationTypeEnum,
        defaultPolicy: WebNavigationPolicyEnum,
        replacesCurrentHistoryItem: Int32) -> WebNavigationPolicyEnum in 
        
        guard handle != nil else {
            return WebNavigationPolicyIgnore
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            var info = WebFrameNavigationPolicyInfo(urlRequest: WebURLRequest(reference: urlRequest!))
            info.extraData = extraData != nil ? WebDataSourceExtraData(reference: extraData!) : nil
            info.navigationType = WebNavigationType(rawValue: Int(navigationType.rawValue))!
            info.defaultPolicy = WebNavigationPolicy(rawValue: Int(defaultPolicy.rawValue))!
            info.replacesCurrentHistoryItem = replacesCurrentHistoryItem == 0 ? false : true
            
            return WebNavigationPolicyEnum(rawValue: UInt32(client.decidePolicyForNavigation(info: info).rawValue))
        }

        return WebNavigationPolicyIgnore
    }

    callbacks.allowContentInitiatedDataUrlNavigations = { (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?) -> CInt in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        return client.allowContentInitiatedDataUrlNavigations(url: String(cString: url!)) ? 1 : 0
      }
      return 0
    }

    callbacks.didStartLoading = { (handle: UnsafeMutableRawPointer?, toDifferentDocument: Int32) in 
      guard handle != nil else {
          return
      }

      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

      if let client = frame.client {
          client.didStartLoading(toDifferentDocument: toDifferentDocument == 0 ? false : true)
      }
    }

    callbacks.didStopLoading = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didStopLoading()
        }
    }

    callbacks.didChangeLoadProgress = { (handle: UnsafeMutableRawPointer?, loadProgress: Double) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didChangeLoadProgress(loadProgress: loadProgress)
        }
    }

    callbacks.willSendSubmitEvent = { (handle: UnsafeMutableRawPointer?, 
        //targetFrame: WebFrameRef?, 
        formElement: WebNodeRef?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.willSendSubmitEvent(
                frame: frame,//WebFrame(reference: targetFrame!), 
                element: WebFormElement(reference: formElement!))
        }

    }

    callbacks.willSubmitForm = { (handle: UnsafeMutableRawPointer?, 
        //targetFrame: WebFrameRef?, 
        formElement: WebNodeRef?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.willSubmitForm(
                frame: frame,
                element: WebFormElement(reference: formElement!))
        }

    }

    callbacks.didStartProvisionalLoad = { (handle: UnsafeMutableRawPointer?, 
        loader: WebDocumentLoaderRef?, 
        urlRequest: WebURLRequestRef?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didStartProvisionalLoad(
                loader: loader != nil ? WebDocumentLoader(reference: loader!) : nil,
                urlRequest: WebURLRequest(reference: urlRequest!))
        }
    }

    callbacks.didReceiveServerRedirectForProvisionalLoad = { (handle: UnsafeMutableRawPointer?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didReceiveServerRedirectForProvisionalLoad(
                frame: frame)
        }
    }

    callbacks.didFailProvisionalLoad = { (handle: UnsafeMutableRawPointer?,
        domain: UnsafePointer<CChar>?,
        reason: Int32,
        hasCopyInCache: Int32,
        isWebSecurityViolation: CInt,
        type: WebHistoryCommitEnum) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
        
        let error = WebURLError(
            domain: String(cString: domain!),
            reason: reason,
            staleCopyInCache: hasCopyInCache == 0 ? false : true,
            isCancellation: false,
            wasIgnoredByHandler: false,
            unreachableURL: String(),
            localizedDescription: String())

        if let client = frame.client {
            client.didFailProvisionalLoad(
                error: error,
                type: WebHistoryCommitType(rawValue: Int(type.rawValue))!
            )
        }
    }

    callbacks.didCommitProvisionalLoad = { (handle: UnsafeMutableRawPointer?, 
        item: WebHistoryItemRef?, 
        type: WebHistoryCommitEnum) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {

            client.didCommitProvisionalLoad(
                item: WebHistoryItem(reference: item!), 
                type: WebHistoryCommitType(rawValue: Int(type.rawValue))!)
        }

    }

    callbacks.didCreateNewDocument = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didCreateNewDocument()
        }

    }

    callbacks.didClearWindowObject = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didClearWindowObject()
        }
    
    }

    callbacks.didCreateDocumentElement = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
          return
      }

      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

      if let client = frame.client {
        client.didCreateDocumentElement()
      }
    }

    callbacks.runScriptsAtDocumentElementAvailable = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

      if let client = frame.client {
        client.runScriptsAtDocumentElementAvailable()
      }
    }

    callbacks.didReceiveTitle = { (handle: UnsafeMutableRawPointer?, 
        title: UnsafePointer<UInt16>?, 
        titleCount: CInt,
        direction: WebTextDirectionEnum) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didReceiveTitle(
                frame: frame, 
                title: String(utf16CodeUnits: title!, count: Int(titleCount)), 
                direction: TextDirection(rawValue: Int(direction.rawValue))!)
        }

    }

    callbacks.didChangeIcon = { (handle: UnsafeMutableRawPointer?, 
        type: WebIconURLEnum) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didChangeIcon(
                frame: frame,
                type: WebIconUrlType(rawValue: Int(type.rawValue)))
        }

    }

    callbacks.didFinishDocumentLoad = { (handle: UnsafeMutableRawPointer?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didFinishDocumentLoad()
        }
    }

    callbacks.runScriptsAtDocumentReady = { (handle: UnsafeMutableRawPointer?, documentIsEmpty: CInt) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.runScriptsAtDocumentReady(documentIsEmpty: documentIsEmpty != 0)
      }
    }

    callbacks.runScriptsAtDocumentIdle = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.runScriptsAtDocumentIdle()
      } 
    }

    callbacks.didHandleOnloadEvents = { (handle: UnsafeMutableRawPointer?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didHandleOnloadEvents()
        }
    }

    callbacks.didFailLoad = { (handle: UnsafeMutableRawPointer?,
        domain: UnsafePointer<CChar>?,
        reason: Int32,
        hasCopyInCache: Int32,
        isWebSecurityViolation: CInt,
        type: WebHistoryCommitEnum) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            
            var error = WebURLError()

            error.domain = String(cString: domain!)
            error.reason = reason
            error.staleCopyInCache = hasCopyInCache == 0 ? false : true

            client.didFailLoad(
                error: error,
                type: WebHistoryCommitType(rawValue: Int(type.rawValue))!)
        }
    }

    callbacks.didFinishLoad = { (handle: UnsafeMutableRawPointer?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didFinishLoad()
        }
    }

    callbacks.didNavigateWithinPage = { (handle: UnsafeMutableRawPointer?,
        item: WebHistoryItemRef?, 
        type: WebHistoryCommitEnum,
        contentInitiated: CInt) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didNavigateWithinPage(
                frame: frame,
                item: WebHistoryItem(reference: item!), 
                type: WebHistoryCommitType(rawValue: Int(type.rawValue))!,
                contentInitiated: contentInitiated != 0)
        }
    }

    callbacks.didUpdateCurrentHistoryItem = { (handle: UnsafeMutableRawPointer?) in//, targetFrame: WebFrameRef?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didUpdateCurrentHistoryItem(frame: frame)
        }
    }

    callbacks.didChangeManifest = { (handle: UnsafeMutableRawPointer?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didChangeManifest(frame: frame)
        }
    }

    callbacks.didChangeThemeColor = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didChangeThemeColor()
        }
    }

    callbacks.forwardResourceTimingToParent = { (handle: UnsafeMutableRawPointer?) in
      guard handle != nil else {
        return
      }

      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.forwardResourceTimingToParent()
      }
    }

    callbacks.dispatchLoad = { (handle: UnsafeMutableRawPointer?) in 
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.dispatchLoad()
        }
    }

    callbacks.getEffectiveConnectionType = { (handle: UnsafeMutableRawPointer?) -> WebEffectiveConnectionTypeEnum in
      //print("WebLocalFrame.getEffectiveConnectionType callback: NOT IMPLEMENTED")
      return WebEffectiveConnectionTypeEnum(rawValue: 0)
    }

    callbacks.getPreviewsStateForFrame = { (handle: UnsafeMutableRawPointer?) -> CInt in
      //print("WebLocalFrame.getPreviewsStateForFrame callback: NOT IMPLEMENTED")
      //return 0
      // kPreviewsOff = 1 << 5
      return 32 
    }

    callbacks.didBlockFramebust = { (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didBlockFramebust(url: String(cString: url!))
      }
    }

    callbacks.abortClientNavigation = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.abortClientNavigation()
      }
    }

    callbacks.pushClient = { (handle: UnsafeMutableRawPointer?) -> WebPushClientRef? in 
      guard handle != nil else {
          return nil
      }

      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let pushClient = frame.client?.pushClient {
          return pushClient.reference
      }

      return nil 
    }

    callbacks.didChangeSelection = { (handle: UnsafeMutableRawPointer?, isSelectionEmpty: Int32) in 
      guard handle != nil else {
          return
      }

      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
          client.didChangeSelection(isSelectionEmpty: isSelectionEmpty == 0 ? false : true)
      }
    }

    callbacks.didChangeContents = { (handle: UnsafeMutableRawPointer?) in 
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didChangeContents()
      }
    }

    callbacks.handleCurrentKeyboardEvent = { (handle: UnsafeMutableRawPointer?) -> CInt in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        return client.handleCurrentKeyboardEvent ? 1 : 0
      }
      return 0
    }

    callbacks.runModalAlertDialog = { (handle: UnsafeMutableRawPointer?, message: UnsafePointer<CChar>?) in   
      guard handle != nil else {
          return
      }

      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
          client.runModalAlertDialog(message: String(cString: message!))
      }
    }

    callbacks.runModalConfirmDialog = { (handle: UnsafeMutableRawPointer?, 
        message: UnsafePointer<CChar>?) -> Int32 in 
        
        guard handle != nil else {
            return 0
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            return client.runModalConfirmDialog(message: String(cString: message!)) ? 1 : 0
        }

        return 0
    }

    callbacks.runModalPromptDialog = { (handle: UnsafeMutableRawPointer?, 
        message: UnsafePointer<CChar>?,
        defaultValue: UnsafePointer<CChar>?,
        actualValue: UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> Int32 in

        guard handle != nil else {
            return 0
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            var actualString = String()

            if let actualCStr = actualValue?[0] {
                actualString = String(cString: actualCStr)               
            }

            return client.runModalPromptDialog(
                message: String(cString: message!), 
                defaultValue: String(cString: defaultValue!),
                actualValue: actualString) ? 1 : 0
        }

        return 0
    }

    callbacks.runModalBeforeUnloadDialog = { (handle: UnsafeMutableRawPointer?, 
        isReload: Int32) -> Int32 in
        
        guard handle != nil else {
            return 0
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            return client.runModalBeforeUnloadDialog(
                isReload: isReload == 0 ? false : true) ? 1 : 0//, 
        }

        return 0
    }

    // callbacks.runFileChooser = { (
    //   handle: UnsafeMutableRawPointer?,
    //   multiSelect: CInt,
    //   directory: CInt,
    //   saveAs: CInt,
    //   title: UnsafePointer<CChar>?,
    //   acceptTypes: UnsafePointer<UnsafeMutablePointer<CChar>?>?,
    //   selectedFiles: UnsafePointer<UnsafeMutablePointer<CChar>?>?,
    //   capture: UnsafePointer<CChar>?,
    //   useMediaCapture: CInt,
    //   needLocalPath: CInt,
    //   requestor: UnsafePointer<CChar>?, 
    //   completion: UnsafeMutableRawPointer?) in
    //   //print("WebLocalFrame.runFileChooser callback: NOT IMPLEMENTED")
    // }

    callbacks.showContextMenu = { (handle: UnsafeMutableRawPointer?, menuData: WebContextMenuDataRef?) in   
      guard handle != nil else {
          return
      }

      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
          client.showContextMenu(data: WebContextMenuData(reference: menuData!))
      }
    }

    callbacks.saveImageFromDataURL = { (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.saveImageFromDataURL(url: String(cString: url!))
      }
    }

    callbacks.willSendRequest = { (handle: UnsafeMutableRawPointer?, 
        req: WebURLRequestRef?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
        
            client.willSendRequest(
                frame: frame,
                request: WebURLRequest(reference: req!))
        }
    }

    callbacks.didReceiveResponse = { (handle: UnsafeMutableRawPointer?,
        resp: WebURLResponseRef?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {

            client.didReceiveResponse(
                frame: frame,
                response: WebURLResponse(reference: resp!))
        }
    }

    callbacks.didLoadResourceFromMemoryCache = { (handle: UnsafeMutableRawPointer?,
        req: WebURLRequestRef?, 
        resp: WebURLResponseRef?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            
            client.didLoadResourceFromMemoryCache(
                frame: frame,
                request: WebURLRequest(reference: req!), 
                response: WebURLResponse(reference: resp!))
        }
    }

    callbacks.didDisplayInsecureContent = { (handle: UnsafeMutableRawPointer?) in   
      guard handle != nil else {
          return
      }

      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didDisplayInsecureContent()
      }
    }

    callbacks.didContainInsecureFormAction = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didContainInsecureFormAction()
      }
    }

    callbacks.didRunInsecureContent = { (handle: UnsafeMutableRawPointer?,
        origin: WebSecurityOriginRef?, 
        insecureURL: UnsafePointer<CChar>?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {

            client.didRunInsecureContent(
                origin: WebSecurityOrigin(reference: origin!),
                insecureURL: String(cString: insecureURL!))
        }
    }

    callbacks.didDetectXSS = { (handle: UnsafeMutableRawPointer?,
        url: UnsafePointer<CChar>?,
        didBlockEntirePage: Int32) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didDetectXSS(
                url: String(cString: url!),
                didBlockEntirePage: didBlockEntirePage == 0 ? false : true)
        }

    }

    callbacks.didDispatchPingLoader = { (handle: UnsafeMutableRawPointer?,
        url: UnsafePointer<CChar>?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
          client.didDispatchPingLoader(
            frame: frame,
            url: String(cString: url!))
        }
    }

    callbacks.didDisplayContentWithCertificateErrors = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didDisplayContentWithCertificateErrors()
      }  
    } 

    callbacks.didRunContentWithCertificateErrors = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.didRunContentWithCertificateErrors()
      }  
    }

    callbacks.didChangePerformanceTiming = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didChangePerformanceTiming()
        }

    }

    callbacks.didCreateScriptContext = { (handle: UnsafeMutableRawPointer?,
        context: JavascriptContextRef?,
        worldId: Int32) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {

            client.didCreateScriptContext(
                context: JavascriptContext(reference: context!),
                worldId: Int(worldId))

        }
    }

    callbacks.willReleaseScriptContext = { (handle: UnsafeMutableRawPointer?,
        context: JavascriptContextRef?, 
        worldId: Int32) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.willReleaseScriptContext(
                context: JavascriptContext(reference: context!), 
                worldId: Int(worldId))
        }
    }

    callbacks.didChangeScrollOffset = { (handle: UnsafeMutableRawPointer?) in
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.didChangeScrollOffset()
        }
    }

    callbacks.willInsertBody = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.willInsertBody(frame: frame)
        }
    }

    callbacks.draggableRegionsChanged = { (handle: UnsafeMutableRawPointer?) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.draggableRegionsChanged()
      } 
    }

    callbacks.scrollRectToVisibleInParentFrame = { (handle: UnsafeMutableRawPointer?,
      x: CInt,
      y: CInt,
      w: CInt,
      h: CInt) in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        client.scrollRectToVisibleInParentFrame(IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h)))
      } 
    }

    callbacks.reportFindInPageMatchCount = { (handle: UnsafeMutableRawPointer?,
        identifier: Int32, 
        count: Int32, 
        finalUpdate: Int32) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {

            client.reportFindInPageMatchCount(
                identifier: Int(identifier),
                count: Int(count),
                finalUpdate: finalUpdate == 0 ? false : true)
        }
    }


    callbacks.reportFindInPageSelection = { (handle: UnsafeMutableRawPointer?, 
        identifier: Int32, 
        activeMatchOrdinal: Int32, 
        x: Int32, 
        y: Int32, 
        w: Int32, 
        h: Int32) in 

        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.reportFindInPageSelection(
                identifier: Int(identifier), 
                activeMatchOrdinal: Int(activeMatchOrdinal), 
                selection: IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h)))
        }
    }


    callbacks.willStartUsingPeerConnectionHandler = { (
        handle: UnsafeMutableRawPointer?,
        handler: WebRTCPeerConnectionHandlerRef?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.willStartUsingPeerConnectionHandler(
                frame: WebFrame(reference: handle!),
                handler: WebRTCPeerConnectionHandler(reference: handler!))
        }
    }

    callbacks.userMediaClient = { (handle: UnsafeMutableRawPointer?) -> WebUserMediaClientRef? in 
        
        guard handle != nil else {
            return nil
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let mediaClient = frame.client?.userMediaClient {
            return mediaClient.reference
        }

        return nil
    }

    callbacks.encryptedMediaClient = { (handle: UnsafeMutableRawPointer?) -> WebEncryptedMediaClientRef? in 
        
        guard handle != nil else {
            return nil
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client?.encryptedMediaClient {
            return client.reference
        }

        return nil
    }


    callbacks.userAgentOverride = { (handle: UnsafeMutableRawPointer?) -> UnsafePointer<CChar>? in 
        
//          guard handle != nil else {
//              return nil
//          }

//            let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        // TODO: we need to solve the lifetime problem here.
        //       we cannot pass the inner buffer (const char*) of a string
        //       that will go away as soon as this method ends
        //       
        //       maybe if we are sure that the receiving end creates its own copy
        //       in that case we dont need to worry

        //if let client = frame.client {
        //    let agent = client.userAgentOverride(frame: WebFrame(reference: other!))
        //}

        return nil
    }

    callbacks.doNotTrackValue = { (handle: UnsafeMutableRawPointer?) -> UnsafePointer<CChar>? in 
        
        guard handle != nil else {
            return nil
        }

        return nil
    }

    callbacks.shouldBlockWebGL = { (handle: UnsafeMutableRawPointer?) -> CInt in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        return client.shouldBlockWebGL ? 1 : 0
      }
      return 0
    }

    callbacks.postAccessibilityEvent = { (handle: UnsafeMutableRawPointer?,
        obj: WebAXObjectRef?, 
        event: WebAXEventEnum) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client, let objRef = obj {
            client.postAccessibilityEvent(
                object: WebAXObject(reference: objRef), 
                event: WebAXEvent(rawValue: Int(event.rawValue))!)
        }
    }

    callbacks.frameRectsChanged = { (
      handle: UnsafeMutableRawPointer?,
      x: CInt, 
      y: CInt, 
      w: CInt, 
      h: CInt) in
    
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
    
      if let client = frame.client {
        client.frameRectsChanged(rect: IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h)))
      }
    }

    callbacks.handleAccessibilityFindInPageResult = { (handle: UnsafeMutableRawPointer?,
        identifier: Int32,
        matchIndex: Int32,
        startObject: WebAXObjectRef?,
        startOffset: Int32,
        endObject: WebAXObjectRef?,
        endOffset: Int32) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.handleAccessibilityFindInPageResult(
                identifier: Int(identifier),
                matchIndex: Int(matchIndex),
                startObject: WebAXObject(reference: startObject!),
                startOffset: Int(startOffset),
                endObject: WebAXObject(reference: endObject!),
                endOffset: Int(endOffset))
        }
    }

    callbacks.enterFullscreen = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            let _ = client.enterFullscreen()
        }
    }

    callbacks.exitFullscreen = { (handle: UnsafeMutableRawPointer?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            let _ = client.exitFullscreen()
        }
    }

    callbacks.suddenTerminationDisablerChanged = { (handle: UnsafeMutableRawPointer?,
        present: Int32, 
        type: WebSuddenTerminationDisablerTypeEnum) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.suddenTerminationDisablerChanged(
                present: present == 0 ? false : true, 
                type: WebFrameSuddenTerminationDisablerType(rawValue: Int(type.rawValue))!)
        }
    }

    callbacks.registerProtocolHandler = { (handle: UnsafeMutableRawPointer?,
        scheme: UnsafePointer<CChar>?,
        url: UnsafePointer<CChar>?,
        title: UnsafePointer<CChar>?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.registerProtocolHandler(
                scheme: String(cString: scheme!), 
                url: String(cString: url!), 
                title: String(cString: title!))
        }
    }

    callbacks.unregisterProtocolHandler = { (handle: UnsafeMutableRawPointer?,
        scheme: UnsafePointer<CChar>?,
        url: UnsafePointer<CChar>?) in 
        
        guard handle != nil else {
            return
        }

        let frame = unsafeBitCast(handle, to: WebLocalFrame.self)

        if let client = frame.client {
            client.unregisterProtocolHandler(
                scheme: String(cString: scheme!),
                url: String(cString: url!))
        }
    }

    callbacks.visibilityState = { (handle: UnsafeMutableRawPointer?) -> WebPageVisibilityStateEnum in
      let frame = unsafeBitCast(handle, to: WebLocalFrame.self)
      if let client = frame.client {
        return WebPageVisibilityStateEnum(rawValue: UInt32(client.visibilityState.rawValue))
      }
      return WebPageVisibilityStateEnum(rawValue: UInt32(WebPageVisibilityState.Visible.rawValue))
    }

    return callbacks
}