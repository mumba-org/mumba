// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Compositor

public enum WebNodeType : Int {
  case Element                = 1
  case Attribute              = 2
  case Text                   = 3
  case CDATASection           = 4
  case ProcessingInstruction  = 7
  case Comment                = 8
  case Document               = 9
  case DocumentType           = 10
  case DocumentFragment       = 11
}

public protocol EventListener {
  func handleEvent(_: Event)
}

public typealias ListenerCallback = (_: Event) -> Void

public class WebNode : ListenerHolderOwner {

  public var type: WebNodeType {
    return WebNodeType(rawValue: Int(_WebNodeGetType(reference)))!
  }

  public var parent: WebNode? {
    let ptr = _WebNodeGetParentNode(reference)
    if ptr == nil {
      return nil
    }
    return WebNode(reference: ptr!)
  }

  public var nodeValue: String {
    let cstr = _WebNodeGetNodeValue(reference)
    return String(cString: cstr!)
  }
  
  public var document: WebDocument? {
    let ptr = _WebNodeGetDocument(reference)
    if ptr == nil {
      return nil
    }
    return WebDocument(reference: ptr!)
  }
  
  public var firstChild: WebNode? {
    let ptr = _WebNodeFirstChild(reference)
    if ptr == nil {
      return nil
    }
    return WebNode(reference: ptr!)
  }

  public var lastChild: WebNode? {
    let ptr = _WebNodeLastChild(reference)
    if ptr == nil {
      return nil
    }
    return WebNode(reference: ptr!)
  }

  public var previousSibling: WebNode? {
    let ptr = _WebNodePreviousSibling(reference)
    if ptr == nil {
      return nil
    }
    return WebNode(reference: ptr!)
  }

  public var nextSibling: WebNode? {
    let ptr = _WebNodeNextSibling(reference)
    if ptr == nil {
      return nil
    }
    return WebNode(reference: ptr!)
  }

  public var hasChildren: Bool {
    return _WebNodeHasChildNodes(reference) == 1
  }

  public var isLink: Bool {
    return _WebNodeIsLink(reference) == 1
  }

  public var isEditingText: Bool {
    return _WebNodeIsEditingText(reference) == 1 
  }

  public var isDocumentNode: Bool {
    return _WebNodeIsDocumentNode(reference) == 1
  }
  
  public var isCommentNode: Bool {
    return type == .Comment
  }
  
  public var isTextNode: Bool {
    return _WebNodeIsTextNode(reference) == 1
  }

   public var isElementNode: Bool {
    return _WebNodeIsElementNode(reference) == 1
  }
  
  public var isFocusable: Bool {
    return _WebNodeIsFocusable(reference) == 1
  }

  public var isContainerNode: Bool {
    return _WebNodeIsContainerNode(reference) == 1
  }

  public var isHtmlElement: Bool {
    return _WebNodeIsHTMLElement(reference) == 1
  }

  public var isSVGElement: Bool {
    return _WebNodeIsSVGElement(reference) == 1
  }

  public var isCustomElement: Bool {
    return _WebNodeIsCustomElement(reference) == 1
  }

  public var isStyledElement: Bool {
    return _WebNodeIsStyledElement(reference) == 1
  }

  public var isDocumentFragment: Bool {
    return _WebNodeIsDocumentFragment(reference) == 1
  }

  public var isShadowRoot: Bool {
    return _WebNodeIsShadowRoot(reference) == 1
  }

  public var isFocused: Bool {
    get {
      return _WebNodeIsFocused(reference) == 1
    }
    // void SetFocused(bool flag, WebFocusType);
    set {
      _WebNodeSetFocused(reference, newValue ? 1 : 0)
    }
  }

  public var hasFocusWithin: Bool {
    get {
      return _WebNodeHasFocusWithin(reference) == 1
    }
    set {
      // void SetHasFocusWithin(bool flag);
      _WebNodeSetHasFocusWithin(reference, newValue ? 1 : 0)
    }
  }

  public var wasFocusedByMouse: Bool {
    get {
      return _WebNodeWasFocusedByMouse(reference) == 1
    }
    set {
      // void SetWasFocusedByMouse(bool flag)
      _WebNodeSetWasFocusedByMouse(reference, newValue ? 1 : 0)
    }
  }

  public var isActive: Bool {
    get {
      return _WebNodeIsActive(reference) == 1
    }
    set {
      // void SetActive(bool flag = true)
      _WebNodeSetActive(reference, newValue ? 1 : 0)
    }
  }

  public var inActiveChain: Bool {
    return _WebNodeInActiveChain(reference) == 1
  }

  public var isDragged: Bool {
    get {
      return _WebNodeIsDragged(reference) == 1
    }
    set {
      //void SetDragged(bool flag)
      _WebNodeSetDragged(reference, newValue ? 1 : 0)
    }
  }

  public var isHovered: Bool {
    get {
      return _WebNodeIsHovered(reference) == 1
    }
    set {
      // void SetHovered(bool flag = true)
      _WebNodeSetHovered(reference, newValue ? 1 : 0)
    }
  }

  public var isInert: Bool {
    return _WebNodeIsInert(reference) == 1
  }
  
  public var ownerShadowHost: WebElement? {
    let ref = _WebNodeOwnerShadowHost(reference)
    return ref != nil ? WebElement(reference: ref!) : nil 
  }
  
  public var containingShadowRoot: WebShadowRoot? {
    let ref = _WebNodeContainingShadowRoot(reference)
    return ref != nil ? WebShadowRoot(reference: ref!) : nil
  }

  public var shadowRoot: WebShadowRoot? {
    let ref = _WebNodeShadowRoot(reference)
    return ref != nil ? WebShadowRoot(reference: ref!) : nil
  }

  public var pluginContainer: WebPluginContainer? {
    return nil
  }

  public var isInsideFocusableElement: Bool {
    return _WebNodeIsInsideFocusableElement(reference) == 1
  }

  public var accessibilityObject: WebAXObject? {

    guard let axRef = _WebNodeGetAccessibilityObject(reference) else {
      return nil
    }
    return WebAXObject(reference: axRef)
  }

  public var textContent: String {
    get {
     let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _WebNodeGetTextContent(reference, selfptr, {
        (peer: UnsafeMutableRawPointer?, data: UnsafePointer<Int8>?, size: Int) in
         let this = unsafeBitCast(peer, to: WebNode.self)
         this._textContent = String(cString: data!)
      })
      return _textContent
    }
    set {
      newValue.withCString {
        _WebNodeSetTextContent(reference, $0)
      }
    }
  }

  public var boundingBox: IntRect {
    var x: CInt = 0
    var y: CInt = 0 
    var w: CInt = 0
    var h: CInt = 0 
    _WebNodeGetBoundingBox(reference, &x, &y, &w, &h)
    return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  }

  public var contentsLayer: Layer? {
    let ref = _WebNodeGetContentsLayer(reference)
    return ref != nil ? Layer(reference: ref!) : nil
  }

  var reference: WebNodeRef
  private var _textContent: String = String()
  private var listeners: [ListenerHolder] = []
  internal var movedByCastToElement: Bool = false

  init(reference: WebNodeRef) {
    self.reference = reference
  }

  deinit {
    guard !movedByCastToElement else {
      return
    }
    _WebNodeRelease(reference)
  }

  public static func hasEditableStyle(_ node: WebNode) -> Bool {
    return _WebNodeHasEditableStyle(node.reference) != 0
  }

  public func isEqual(to other: WebNode) -> Bool {
    return _WebNodeIsEqual(reference, other.reference) == 1
  }
  
  public func lessThan(other: WebNode) -> Bool {
    return _WebNodeLessThan(reference, other.reference) == 1
  }

  public func dispatchEvent(event: Event) {
    _WebNodeDispatchEvent(reference, event.reference)
  }
  
  public func getElementsByTagName(_ tag: String) -> HtmlCollection? {
    var ref: HTMLCollectionRef? = nil
    tag.withCString { cstr in
      ref = _WebNodeGetElementsByTagName(reference, cstr)
    }
    return ref == nil ? nil : HtmlCollection(reference: ref!)
  }

  public func query(_ selector: String) -> WebElement? {
    var ptr: WebNodeRef? = nil
    
    selector.withCString { cstr in
       ptr = _WebNodeQuerySelector(reference, cstr)
    }

    return ptr == nil ? nil : WebElement(reference: ptr!)
  }

  public func query(_ selector: String, exception: inout WebExceptionCode) -> WebElement? {
    var ref: WebNodeRef? = nil
    var errcode: Int32 = 0
    
    exception = .None
    
    selector.withCString { cstr in
      ref = _WebNodeQuerySelectorException(reference, cstr, &errcode)
    }

    if errcode > 0 {
      exception = WebExceptionCode(rawValue: Int(errcode))!
    }
    
    return ref == nil ? nil : WebElement(reference: ref!)
  }
  
  public func queryAll(_ selector: String) -> WebElementArray? {
    var ref: WebElementArrayRef? = nil
    selector.withCString { cstr in
      ref = _WebNodeQuerySelectorAll(reference, cstr)
    }
    return ref == nil ? nil : WebElementArray(reference: ref!)
  }

  public func queryAll(_ selector: String, exception: inout WebExceptionCode) -> WebElementArray? {
    var ref: WebElementArrayRef? = nil
    var code: Int32 = 0
   
    exception = .None
 
    selector.withCString { cstr in
      ref = _WebNodeQuerySelectorAllException(reference, cstr, &code)
    }
    
    if code > 0 {
      exception = WebExceptionCode(rawValue: Int(code))!
    }
    
    return ref == nil ? nil : WebElementArray(reference: ref!)
  }

  public func insertBefore(_ node: WebNode, anchor: WebNode) -> WebNode {
    let ref = _WebNodeInsertBefore(reference, node.reference, anchor.reference)
    return WebNode(reference: ref!)
  }

  public func replaceChild(_ newChild: WebNode, old: WebNode) -> WebNode {
    let ref = _WebNodeReplaceChild(reference, newChild.reference, old.reference)
    return WebNode(reference: ref!)
  }

  public func removeChild(_ child: WebNode) -> WebNode {
    let ref = _WebNodeRemoveChild(reference, child.reference)
    return WebNode(reference: ref!)
  }

  public func appendChild(_ child: WebNode) -> WebNode {
    let ref = _WebNodeAppendChild(reference, child.reference)
    return WebNode(reference: ref!)
  }

  public func clone(deep: Bool) -> WebNode {
    let ref = _WebNodeClone(reference, deep ? 1 : 0)
    return WebNode(reference: ref!)
  }

  public func isDescendantOf(node: WebNode) -> Bool {
    return _WebNodeIsDescendantOf(reference, node.reference) == 1
  }
  
  public func contains(node: WebNode) -> Bool {
    return _WebNodeContains(reference, node.reference) == 1
  }

  public func addEventListener(
    _ event: String,
    listener: EventListener) -> Bool {
    let state = ListenerHolder(event: event, listener: listener)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    return event.withCString {
      return _WebNodeAddEventListener(reference, $0, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
        let holder = unsafeBitCast(handle, to: ListenerHolder.self)
        holder.listener!.handleEvent(Event(reference: evhandle!))
        //holder.dispose()
      }) != 0
    }
  }

  public func addEventListener(
    _ event: String,
    _ listenerCallback: @escaping ListenerCallback) -> Bool {
    let state = ListenerHolder(event: event, callback: listenerCallback)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    return event.withCString {
      return _WebNodeAddEventListener(reference, $0, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
        let holder = unsafeBitCast(handle, to: ListenerHolder.self)
        if let cb = holder.callback {
          cb(Event(reference: evhandle!))
        }
        //holder.dispose()
      }) != 0
    }
  }
  
  public func removeEventListener(
    _ event: String,
    listener: EventListener) -> Bool {
    var index: Int = 0
    var maybeHolder: ListenerHolder?
    for (i, listener) in listeners.enumerated() {
      if listener.event == event {
        index = i
        maybeHolder = listener
        break
      }
    }
    guard let state = maybeHolder else {
      return false
    }
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let result = event.withCString {
      return _WebNodeRemoveEventListener(reference, $0, listenerState) != 0
    }
    listeners.remove(at: index)
    return result
  }

  public func removeAllEventListeners() {
    _WebNodeRemoveAllEventListeners(reference)
  }

  public func destroy(_ holder: ListenerHolder) {
    for (i, item) in listeners.enumerated() {
      if item === holder {
        listeners.remove(at: i)
      }
    }
  }

}

extension WebNode : Equatable {
  
  public static func == (lhs: WebNode, rhs: WebNode) -> Bool {
    return lhs.isEqual(to: rhs)
  }

}

public protocol ListenerHolderOwner : class {
  func destroy(_ : ListenerHolder)
}

public class ListenerHolder {

  var event: String
  var listener: EventListener?
  var callback: ListenerCallback?
  weak var owner: ListenerHolderOwner?
  
  init(event: String, listener: EventListener) {
    //self.owner = owner
    self.event = event
    self.listener = listener
  }

  init(event: String, callback: @escaping ListenerCallback) {
    //self.owner = owner
    self.event = event
    self.callback = callback
  }

  public func dispose() {
    owner?.destroy(self)
  }

}
