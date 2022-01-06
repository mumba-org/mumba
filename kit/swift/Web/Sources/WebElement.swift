// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class WebElement : WebContainerNode {

  public var isFormControlElement: Bool {
    return _WebElementIsFormControlElement(reference) == 1
  }

  public var isTextControlElement: Bool {
    return _WebElementIsTextControlElement(reference) == 1
  }

  // public var isHtmlElement: Bool {
  //  return _WebElementIsHtmlElement(reference) == 1
  // }

  public var isEditable: Bool {
    return _WebElementIsEditable(reference) == 1
  }

  public var tagName: String {
    let resultCStr = _WebElementGetTagName(reference)
    return String(cString: resultCStr!)
  }

  // public var textContent: String {
  //   let resultCStr = _WebElementGetTextContext(reference)
  //   return String(cString: resultCStr!)
  // }
  
  public var imageContents: Image {
    let imageHandle  = _WebElementGetImageContents(reference)
    return ImageSkia(reference: imageHandle!)
  }
  
  public var boundsInViewportSpace: IntRect {
    var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
    _WebElementGetBoundsInViewportSpace(reference, &x, &y, &w, &h)
    return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  }
  
  public var attributeCount: Int {
    return Int(_WebElementGetAttributeCount(reference))
  }

  public var hasNonEmptyLayoutSize: Bool {
    return _WebElementHasNonEmptyLayoutSize(reference) == 1
  }

  // public var shadowRoot: WebShadowRoot? {
  //   if let ref = _WebElementGetShadowRoot(reference) {
  //     return WebShadowRoot(reference: ref)
  //   }
  //   return nil
  // }

  public var innerHTML: String {
    get {
      var len: CInt = 0 
      let cstr = _innerHtml.withCString {
        return _WebElementGetInnerHtml(reference, $0, &len)
      }
      // the old value is passed for comparison
      // if nil is returned it means that is empty or
      // that its the same as the value given for comparison
      guard cstr != nil else {
        return _innerHtml
      }
      _innerHtml = String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      return _innerHtml
    }
    set {
      _innerHtml = newValue
      _innerHtml.withCString {
        _WebElementSetInnerHtml(reference, $0, CInt(_innerHtml.count))
      }
    }
  }

  public var outerHTML: String {
    get {
      let ref = _WebElementGetOuterHtml(reference)
      return ref != nil ? String(cString: ref!) : String()
    }
    set {
      newValue.withCString {
        _WebElementSetOuterHtml(reference, $0, CInt(newValue.count))
      }  
    }
  }

  // public subscript(dynamicMember name: String) -> String {
  //   get {
  //     return getAttribute(attribute: name)
  //   }
  //   set {
  //     setAttribute(name: name, value: newValue)
  //   }
  // }

  var _innerHtml: String = String()

  public func hasTagName(_ tag: String) -> Bool {
    var result = false
    tag.withCString { cstr in
      result = _WebElementHasTagName(reference, cstr) == 1
    }
    return result
  }
  
  public func hasAttribute(_ attribute: String) -> Bool {
    let result = attribute.withCString { cstr -> Bool in
      return _WebElementHasAttribute(reference, cstr) == 1
    }
    return result
  }
  
  public func removeAttribute(_ attribute: String) {
    attribute.withCString { attrbuf in
      _WebElementRemoveAttribute(reference, attrbuf)
    }
  }
  
  public func getAttribute(_ attribute: String) -> String {
    let result = attribute.withCString { (cstr: UnsafePointer<CChar>) -> UnsafePointer<CChar> in
      return _WebElementGetAttribute(reference, cstr)
    }
    return String(cString: result)
  }
  
  public func setAttribute(_ attribute: String, value: String) -> Bool {
  
    let result = attribute.withCString { namebuf -> Bool in
      value.withCString { valuebuf -> Bool in
        return _WebElementSetAttribute(reference, namebuf, valuebuf) == 1
      }
    }
    
    return result
  }

  public func getIntegralAttribute(_ attribute: String) -> Int {
    return attribute.withCString { (cstr: UnsafePointer<CChar>) -> Int in
      return Int(_WebElementGetIntegralAttribute(reference, cstr))
    }
  }
  
  public func setIntegralAttribute(_ attribute: String, value: Int) {
    attribute.withCString {
      _WebElementSetIntegralAttribute(reference, $0, CInt(value))
    }
  }

  public func setUnsignedIntegralAttribute(_ attribute: String, value: UInt) {
    attribute.withCString {
      _WebElementSetUnsignedIntegralAttribute(reference, $0, UInt32(value))
    }
  }

  public func requestFullScreen() {
    _WebElementRequestFullscreen(reference)
  }

  public func attributeLocalName(index: Int) -> String {
    let cstr = _WebElementAttributeLocalName(reference, Int32(index))
    return String(cString: cstr!)
  }

  public func attributeValue(index: Int) -> String {
    let cstr = _WebElementAttributeValue(reference, Int32(index))
    return String(cString: cstr!)
  }

  public func asHtmlElement<T: HtmlElement>(to type: T.Type) -> T? {
    // we are borrowing our own reference to another object, increment the ref count for it
    // TODO: i guess that with oilpan, we dont need this anymore
    //_WebNodeRetain(reference)
    self.movedByCastToElement = true
    return T(reference: reference)
  }

  public func createShadowRoot() -> WebShadowRoot {
    let ref = _WebElementCreateShadowRoot(reference)
    return WebShadowRoot(reference: ref!)
  }

  public func createUserAgentShadowRoot() -> WebShadowRoot {
    let ref = _WebElementCreateUserAgentShadowRoot(reference)
    return WebShadowRoot(reference: ref!)
  }

  public func attachShadowRoot(type: WebShadowRootType) {
    _WebElementAttachShadowRoot(reference, CInt(type.rawValue))
  }

  public func setInlineStyleProperty(property: String,
                                     value: Double,
                                     type: CSSPrimitiveValueUnitType) {
    property.withCString {
      _WebElementSetInlineStylePropertyDouble(reference, $0, value, CInt(type.rawValue))
    }
  }
  
  public func setInlineStyleProperty(property: String,
                                     value: String) {
    property.withCString { pstr in 
       value.withCString { vstr in
          _WebElementSetInlineStylePropertyString(reference, pstr, vstr)
       }
    }
  }

  public func removeInlineStyleProperty(property: String) -> Bool {
    return property.withCString { 
      return _WebElementRemoveInlineStyleProperty(reference, $0) != 0
    }
  }

  public func removeAllInlineStyleProperties() {
    _WebElementRemoveAllInlineStyleProperties(reference)
  }

}

public class WebFormElement : WebElement {
  
  public enum AutocompleteResult : Int {
    case Success = 0
    case ErrorDisabled = 1
    case ErrorCancel = 2
    case ErrorInvalid = 3
  }

  public var action: String {
    let result = _WebFormElementGetAction(reference)
    if result == nil {
      return String()
    }
    return String(cString: result!)
  }
  
  public var name: String {
    let result = _WebFormElementGetName(reference)
    if result == nil {
      return String()
    }
    return String(cString: result!)
  }
  
  public var method: String {
    let result = _WebFormElementGetMethod(reference)
    if result == nil {
      return String()
    }
    return String(cString: result!)
  }

  //public var wasUserSubmitted: Bool {
  //  return _WebFormElementWasUserSubmitted(reference) == 0 ? false : true
  //}
 
  public var autoComplete: Bool {
    let result = _WebFormElementShouldAutoComplete(reference) == 0 ? false : true
    return result
  }

  public func getNamedElements(name: String) -> [WebElement] {
    var elements: [WebElement] = []
    var elementRefs: [WebNodeRef?] = []
    var elemLen: Int32 = 0
    let maxResults = 1000

    elementRefs.reserveCapacity(maxResults)
    
    name.withCString { namebuf in
      elementRefs.withUnsafeMutableBufferPointer { elembuf in
        _WebFormElementGetNamedElements(reference, namebuf, elembuf.baseAddress, &elemLen)
      }
    }

    for i in 0...Int(elemLen) {
      if let elementRef = elementRefs[i] {
        elements.insert(WebElement(reference: elementRef), at: i)
      }
    }
    
    return elements
  }
  
  // public func getFormControlElements() -> [WebFormControlElement] {
  //   var elements: [WebFormControlElement] = []
  //   var elementRefs: [WebNodeRef?] = []
  //   var elemLen: Int32 = 0
  //   let maxResults = 1000

  //   elementRefs.reserveCapacity(maxResults)
    
  //   elementRefs.withUnsafeMutableBufferPointer { elembuf in
  //     _WebFormElementGetFormControlElements(reference, elembuf.baseAddress, &elemLen)
  //   }

  //   for i in 0...Int(elemLen) {
  //     if let elementRef = elementRefs[i] {
  //       elements.insert(WebFormControlElement(reference: elementRef), at: i)
  //     }
  //   }
    
  //   return elements
  // }

  public func checkValidity() -> Bool {
    let result = _WebFormElementCheckValidity(reference) == 0 ? false : true
    return result
  }

  //public func finishRequestAutocomplete(result: AutocompleteResult) {
  //  _WebFormElementFinishRequestAutocomplete(reference, Int32(result.rawValue))
  //}

}

public class WebFormControlElement : WebElement {
    
    public var isEnabled: Bool {
      return _WebFormControlElementIsEnabled(reference) == 0 ? false : true
    }

    public var isReadOnly: Bool {
      return _WebFormControlElementIsReadonly(reference) == 0 ? false : true
    }

    public var formControlName: String {
      let cstring = _WebFormControlElementGetFormControlName(reference)
      if cstring == nil {
        return String()
      }
      return String(cString: cstring!)
    }

    public var formControlType: String {
      let cstring = _WebFormControlElementGetFormControlType(reference)
      if cstring == nil {
        return String()
      }
      return String(cString: cstring!)
    }

    public var isAutofilled: Bool {
      get {
        return _WebFormControlElementIsAutofilled(reference) == 0 ? false : true
      }
      set {
        _WebFormControlElementSetIsAutofilled(reference, newValue ? 1 : 0)
      }
    }

    public var autoComplete: Bool {
      return _WebFormControlElementShouldAutocomplete(reference) == 0 ? false : true
    }

    public var value: String {
      
      get {
        let cstring = _WebFormControlElementGetValue(reference)
        if cstring == nil {
          return String()
        }
        return String(cString: cstring!)
      }
      
      set {
        newValue.withCString { valuebuf in
          _WebFormControlElementSetValue(reference, valuebuf)
        }
      }
    }

    public var suggestedValue: String {
      
      get {
        let cstring = _WebFormControlElementGetSuggestedValue(reference)
        if cstring == nil {
          return String()
        }
        return String(cString: cstring!)
      }
  
      set {
        newValue.withCString { strbuf in
          _WebFormControlElementSetSuggestedValue(reference, strbuf)
        }
      }
    }

    public var editingValue: String {
      let cstring = _WebFormControlElementGetEditingValue(reference)
      if cstring == nil {
        return String()
      }
      return String(cString: cstring!)
    }

    public var selectionStart: Int {
      let start = _WebFormControlElementGetSelectionStart(reference)
      return Int(start)
    }
    
    public var selectionEnd: Int {
      let end = _WebFormControlElementGetSelectionEnd(reference)
      return Int(end)
    }
    
    public var directionForFormData: String {
      let cstring = _WebFormControlElementGetDirectionForFormData(reference)
      if cstring == nil {
        return String()
      }
      return String(cString: cstring!)
    }
    
    public var nameForAutofill: String {
      let cstring = _WebFormControlElementGetNameForAutofill(reference)
      if cstring == nil {
        return String()
      }
      return String(cString: cstring!)
    }

    public var form: WebFormElement {
      let ref = _WebFormControlElementGetForm(reference)
      return WebFormElement(reference: ref!)
    }

    public func setSelectionRange(start: Int, end: Int) {
      _WebFormControlElementSetSelectionRange(reference, Int32(start), Int32(end))
    }
}


// TODO: make it comply with sequence interface
// also make it more alike with Array<>.. startIndex, endIndex, etc..
public class WebElementArray {

  var count: Int {
    return Int(_WebElementArrayLenght(reference))
  }

  var reference: WebElementArrayRef

  init(reference: WebElementArrayRef) {
    self.reference = reference
  }

  deinit {
    _WebElementArrayDestroy(reference)
  }
  
  public subscript(_ index: Int) -> WebElement? {
    let ref = _WebElementArrayGetElementAt(reference, Int32(index))
    return ref == nil ? nil : WebElement(reference: ref!)
  }

}