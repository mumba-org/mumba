// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Base
import MumbaShims
import Javascript

public enum WebReferrerPolicy : Int {
  case Always = 0
  case Default = 1
  case NoReferrerWhenDowngrade = 2
  case Never = 3
  case Origin = 4
  case OriginWhenCrossOrigin = 5
}

public class WebDocumentLoader {

  public var request: WebURLRequest {
    let ref = _WebDocumentLoaderGetRequest(reference)
    return WebURLRequest(reference: ref!, owned: true)
  }

  public var response: WebURLResponse {
    let ref = _WebDocumentLoaderGetResponse(reference)
    return WebURLResponse(reference: ref!)
  }

  public var serviceWorkerNetworkProvider: WebServiceWorkerNetworkProvider? {
    get {
      return _serviceWorkerNetworkProvider
    }
    set {
      _serviceWorkerNetworkProvider = newValue
      _WebDocumentLoaderSetServiceWorkerNetworkProvider(reference, newValue != nil ? newValue!.reference : nil)
    }
  }

  public var hasUnreachableUrl: Bool {
    return _WebDocumentLoaderHasUnreachableUrl(reference) != 0
  }

  public var url: String {
    var len: CInt = 0
    let cstr = _WebDocumentLoaderGetUrl(reference, &len)
    return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }
 
  internal var reference: WebDocumentLoaderRef
  private var _serviceWorkerNetworkProvider: WebServiceWorkerNetworkProvider?
  
  internal init(reference: WebDocumentLoaderRef) {
    self.reference = reference
  }

  public func setUserActivated() {
    _WebDocumentLoaderSetUserActivated(reference)
  }

  public func resetSourceLocation() {
    _WebDocumentLoaderResetSourceLocation(reference)
  }

  public func setNavigationStartTime(_ time: TimeTicks) {
    _WebDocumentLoaderSetNavigationStartTime(reference, time.microseconds) 
  }

}

public class WebDocumentType : WebNode {
  
  override init(reference: WebNodeRef) {
    super.init(reference: reference)
  }

  public var name: String {
    let resultCStr = _WebDocumentTypeGetName(reference)
    return String(cString: resultCStr!)
  }

}

public class WebDocument : WebContainerNode {

  public var url: String {
    let resultCStr = _WebDocumentGetURL(reference)
    return String(cString: resultCStr!)
  }
  
  public var securityOrigin: WebSecurityOrigin? {
    //return WebSecurityOrigin()
    return nil
  }

  public var location: Location {
    let ref = _WebDocumentGetLocation(reference)
    return Location(reference: ref!)
  }

  public var encoding: String {
    let resultCStr = _WebDocumentGetEncoding(reference)
    return String(cString: resultCStr!)
  }
    
  public var contentLanguage: String {
    let resultCStr = _WebDocumentGetContentLanguage(reference)
    return String(cString: resultCStr!)
  }
    
  public var referrer: String {
    let resultCStr = _WebDocumentGetReferrer(reference)
    return String(cString: resultCStr!)
  }
    
  public var themeColor: Color {
    var a: UInt8 = 0, r: UInt8 = 0, g: UInt8 = 0, b: UInt8 = 0
    _WebDocumentGetThemeColor(reference, &a, &r, &g, &b)
    return Color(a: a, r: r, g: g, b: b)
  }

  public var openSearchDescriptionURL: String {
    let resultCStr = _WebDocumentOpenSearchDescriptionURL(reference)
    return String(cString: resultCStr!)
  }

  public var frame: WebLocalFrame {
    let frameHandle = _WebDocumentGetFrame(reference)
    return WebLocalFrame(reference: frameHandle!)
  }

  public var isHTMLDocument: Bool {
    return _WebDocumentIsHTMLDocument(reference) == 1
  }
  
  public var isXHTMLDocument: Bool {
    return _WebDocumentIsXHTMLDocument(reference) == 1
  }
  
  public var isPluginDocument: Bool {
    return _WebDocumentIsPluginDocument(reference) == 1
  }

  public var isXMLDocument: Bool {
    return _WebDocumentIsXMLDocument(reference) == 1
  }
  
  public var isImageDocument: Bool {
    return _WebDocumentIsImageDocument(reference) == 1
  }
  
  public var isSVGDocument: Bool {
    return _WebDocumentIsSVGDocument(reference) == 1
  }
  
  public var isMediaDocument: Bool {
    return _WebDocumentIsMediaDocument(reference) == 1
  }
  
  public var isSrcdocDocument: Bool {
    return _WebDocumentIsSrcdocDocument(reference) == 1
  }
  
  public var isMobileDocument: Bool {
    return _WebDocumentIsMobileDocument(reference) == 1
  }
  
  public var baseURL: String {
    let resultCStr = _WebDocumentGetBaseURL(reference)
    return String(cString: resultCStr!)
  }

  public var documentElement: WebElement {
    let elemHandle = _WebDocumentGetDocumentElement(reference)
    return WebElement(reference: elemHandle!)
  }

  public var body: WebElement? {
    let elemHandle = _WebDocumentGetBody(reference)
    return elemHandle != nil ? WebElement(reference: elemHandle!) : nil
  }
  
  public var head: WebElement? {
    let elemHandle = _WebDocumentGetHead(reference)
    return elemHandle != nil ? WebElement(reference: elemHandle!) : nil
  }

  public var scrollingElement: WebElement? {
    let elemHandle = _WebDocumentGetScrollingElement(reference)
    return elemHandle != nil ? WebElement(reference: elemHandle!) : nil
  }
  
  public var title: String {
    let resultCStr = _WebDocumentGetTitle(reference)
    return String(cString: resultCStr!)
  }
  
  public var all: HtmlCollection {
    let collectionHandle = _WebDocumentGetAll(reference)
    return HtmlCollection(reference: collectionHandle!)
  }

  public var images: HtmlCollection {
    let collectionHandle = _WebDocumentGetImages(reference)
    return HtmlCollection(reference: collectionHandle!)
  }

  public var embeds: HtmlCollection {
    let collectionHandle = _WebDocumentGetEmbeds(reference)
    return HtmlCollection(reference: collectionHandle!)
  }

  public var applets: HtmlCollection {
    let collectionHandle = _WebDocumentGetApplets(reference)
    return HtmlCollection(reference: collectionHandle!)
  }

  public var links: HtmlCollection {
    let collectionHandle = _WebDocumentGetLinks(reference)
    return HtmlCollection(reference: collectionHandle!)
  }

  public var forms: HtmlCollection {
    let collectionHandle = _WebDocumentGetForms(reference)
    return HtmlCollection(reference: collectionHandle!)
  }

  public var anchors: HtmlCollection {
    let collectionHandle = _WebDocumentGetAnchors(reference)
    return HtmlCollection(reference: collectionHandle!)
  }

  public var scripts: HtmlCollection {
    let collectionHandle = _WebDocumentGetScripts(reference)
    return HtmlCollection(reference: collectionHandle!)
  }

  public var manifestURL: String {
    let resultCStr = _WebDocumentGetManifestURL(reference)
    return String(cString: resultCStr!)
  }

  public var manifestUseCredentials: Bool {
    return _WebDocumentManifestUseCredentials(reference) == 1
  }

  //public var firstPartyForCookies: URL {
  //  let resultCStr = _WebDocumentGetFirstPartyForCookies(reference)
  //  return URL(string: String(cString: resultCStr!))!
  //}

  public var draggableRegions: [WebDraggableRegion] {
    return []
  }

  public var focusedElement: WebElement? {
    let elemHandle = _WebDocumentGetFocusedElement(reference)
    return WebElement(reference: elemHandle!)
  }
  
  public var doctype: WebDocumentType {
    let typeHandle = _WebDocumentGetDoctype(reference)
    return WebDocumentType(reference: typeHandle!)
  }

  public var fullScreenElement: WebElement {
    let elemHandle = _WebDocumentGetFullscreenElement(reference)
    return WebElement(reference: elemHandle!)
  }
  
  public var referrerPolicy: WebReferrerPolicy {
    return .Default
  }
  
  public var outgoingReferrer: String {
    let resultCStr = _WebDocumentOutgoingReferrer(reference)
    return String(cString: resultCStr!)
  }
  
  public override var accessibilityObject: WebAXObject? {
    guard let axRef = _WebDocumentGetAccessibilityObject(reference) else {
      return nil
    }
    return WebAXObject(reference: axRef)
  }

  public var domWindow: WebWindow {
    if _domWindow == nil {
      _domWindow = WebWindow(reference: _WebDocumentGetDomWindow(reference))
    }
    return _domWindow!
  }

  //public init() {
  //  let document = _WebNodeCreate(kDOCUMENT_TYPE)
  //  super.init(reference: document!)
  //}

  private var _domWindow: WebWindow?

  override init(reference: WebNodeRef) {
    super.init(reference: reference)
  }

  public func isSecureContext(errorMessage: String) -> Bool {
    return errorMessage.withCString { cstr -> Bool in
      return _WebDocumentIsSecureContext(reference, cstr) == 0 ? false : true
    }
  }

  public func forms(elements: [WebFormElement]) {
    _WebDocumentForms(reference)
  }
  
  public func completeURL(url: String) -> String? {
    
    let maybeString = url.withCString { urlCStr -> String? in
      
      let maybeCStr = _WebDocumentCompleteURL(reference, urlCStr)
      
      guard let CStrRef = maybeCStr else {
        return nil
      }

      return String(cString: CStrRef)
    }

    guard let urlString = maybeString else {
        return nil
    }

    return urlString
  }

  public override func getElementsByTagName(_ tag: String) -> HtmlCollection? {
    var collectionHandle: HTMLCollectionRef?
    tag.withCString {
      collectionHandle = _WebDocumentGetElementsByTagName(reference, $0)
    }
    return collectionHandle != nil ? HtmlCollection(reference: collectionHandle!) : nil
  }
  
  public func getElementById(_ id: String) -> WebElement? {

    let maybeRef = id.withCString { idstr -> WebNodeRef? in 
      return _WebDocumentGetElementById(reference, idstr)
    }
  
    guard let elemRef = maybeRef else {
      return nil
    }

    return WebElement(reference: elemRef)
  }

  public func createElement(tag: String) -> WebElement {
    let ref = tag.withCString { (cstr: UnsafePointer<Int8>?) -> UnsafeMutableRawPointer? in 
      return _WebDocumentCreateElement(reference, cstr)
    }
    return WebElement(reference: ref!)
  }

  public func createTextNode(_ data: String) -> WebElement {
    let ref = data.withCString { (cstr: UnsafePointer<Int8>?) -> UnsafeMutableRawPointer? in 
      return _WebDocumentCreateTextNode(reference, cstr)
    }
    return WebElement(reference: ref!)
  }
  
  public func cancelFullScreen() {
    _WebDocumentCancelFullScreen(reference)
  }

  public func accessibilityObjectFromID(id: Int) -> WebAXObject? {
    let ref = _WebDocumentAccessibilityObjectFromID(reference, Int32(id))
    if ref == nil {
      return nil
    }
    return WebAXObject(reference: ref!)
  }
  
  public func insertStyleSheet(key: String, sourceCode: String) {
    let keyPtr = key.withCString { (keyCStr: UnsafePointer<Int8>?) -> UnsafePointer<Int8>? in
      return keyCStr  
    }
    let sourcePtr = sourceCode.withCString { (sourceCStr: UnsafePointer<Int8>?) -> UnsafePointer<Int8>? in
      return sourceCStr  
    }
    _WebDocumentInsertStyleSheet(reference, keyPtr, sourcePtr)
  }
  
  public func watchCSSSelectors(selectors: [String]) {
    var cstrSelectors: [UnsafePointer<CChar>?] = []  

    for selector in selectors {
      selector.withCString { cstrSelector in 
        cstrSelectors.append(cstrSelector)
      }
    }

    cstrSelectors.withUnsafeMutableBufferPointer { selectorBuf in
      _WebDocumentWatchCSSSelectors(reference, selectorBuf.baseAddress, Int32(selectors.count))
    }
  }

  public func querySelector(_ query: String) -> SelectorQuery {
    let ref = query.withCString {
      return _WebDocumentQuerySelector(reference, $0)
    }
    return SelectorQuery(container: self, reference: ref!)
  }

  public func registerEmbedderCustomElement(name: String, options: JavascriptValue, exc: WebExceptionCode) -> JavascriptValue {
    
    let ref = name.withCString { (cstr: UnsafePointer<CChar>) -> JavascriptDataRef? in
      return _WebDocumentRegisterEmbedderCustomElement(reference, cstr, options.reference, nil)//exc.rawValue)
    }

    return JavascriptValue(context: JavascriptContext.current, reference: ref!)
  }

  public func caretRangeFromPoint(_ p: IntPoint) -> WebRange? {
    return caretRangeFromPoint(x: p.x, y: p.y)
  }

  public func caretRangeFromPoint(x: Int, y: Int) -> WebRange? {
    let result = _WebDocumentGetCaretRangeFromPoint(reference, CInt(x), CInt(y))
    return result == nil ? nil : WebRange(reference: result!)
  }

  public func updateStyleAndLayoutTree() {
    _WebDocumentUpdateStyleAndLayoutTree(reference)
  }
  
  public func updateStyleAndLayoutTreeIgnorePendingStylesheets() {
    _WebDocumentUpdateStyleAndLayoutTreeIgnorePendingStylesheets(reference)
  }
  
  public func updateStyleAndLayoutTreeForNode(node: WebNode) {
    _WebDocumentUpdateStyleAndLayoutTreeForNode(reference, node.reference)
  }
  
  public func updateStyleAndLayout() {
    _WebDocumentUpdateStyleAndLayout(reference) 
  }

}