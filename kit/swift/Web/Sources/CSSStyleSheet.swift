// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class StyleSheetContents {

  var reference: StyleSheetContentsRef
  
  init(reference: StyleSheetContentsRef) {
    self.reference = reference
  }

}

public class CSSStyleSheet {

  public var baseURL: String {
    let ref = _CSSStyleSheetGetBaseURL(reference)
    return ref != nil ? String(cString: ref!) : String()
  }

  public var isLoading: Bool {
    return _CSSStyleSheetIsLoading(reference) != 0
  }

  public var href: String {
    let ref = _CSSStyleSheetGetHref(reference)
    return ref != nil ? String(cString: ref!) : String()
  }
 
  public var title: String {
    get {
      let ref = _CSSStyleSheetGetTitle(reference)
      return ref != nil ? String(cString: ref!) : String()
    } 
    set {
      newValue.withCString {
        _CSSStyleSheetSetTitle(reference, $0)
      }
    }
  }

  public var disabled: Bool {
    get {
      return _CSSStyleSheetIsDisabled(reference) != 0   
    }
    set {
      _CSSStyleSheetSetIsDisabled(reference, newValue ? 1 : 0)
    }
  }

  public var ownerNode: WebNode? {
    let ref = _CSSStyleSheetOwnerNode(reference)
    return ref != nil ? WebNode(reference: ref!) : nil
  }

  public var parentStyleSheet: CSSStyleSheet? {
    let ref = _CSSStyleSheetGetParentStyleSheet(reference)
    return ref != nil ? CSSStyleSheet(reference: ref!) : nil 
  }

  public var cssRules: CSSRuleList? {
    let ref = _CSSStyleSheetGetCSSRuleList(reference)
    return ref != nil ? CSSRuleList(reference: ref!) : nil  
  }

  public var ownerDocument: WebDocument? {
    let ref = _CSSStyleSheetGetOwnerDocument(reference)
    return ref != nil ? WebDocument(reference: ref!) : nil 
  }
  
  public var length: Int {
    return Int(_CSSStyleSheetGetLenght(reference))
  }

  public var contents: StyleSheetContents? {
    let ref = _CSSStyleSheetGetContents(reference)
    return ref != nil ? StyleSheetContents(reference: ref!) : nil
  }

  public var isInline: Bool {
    return _CSSStyleSheetIsInline(reference) != 0
  }

  public var sheetLoaded: Bool {
    return _CSSStyleSheetIsSheetLoaded(reference) != 0 
  }

  public var loadCompleted: Bool {
    return _CSSStyleSheetIsLoadCompleted(reference) != 0 
  }

  public var isAlternate: Bool {
    return _CSSStyleSheetIsAlternate(reference) != 0 
  }

  var reference: CSSStyleSheetRef

  public static func create(document: WebDocument, name: String, contents: String) -> CSSStyleSheet {
    return name.withCString { (nameCstr: UnsafePointer<Int8>?) -> CSSStyleSheet in
      return contents.withCString { (contentsCstr: UnsafePointer<Int8>?) -> CSSStyleSheet in
        let ref = _CSSStyleSheetCreate(document.reference, nameCstr, contentsCstr)
        //print("_CSSStyleSheetCreate \(ref!)")
        return CSSStyleSheet(reference: ref!)
      }
    }
  }

  public static func create(node: WebNode, name: String, contents: String) -> CSSStyleSheet {
    return name.withCString { (nameCstr: UnsafePointer<Int8>?) -> CSSStyleSheet in
      return contents.withCString { (contentsCstr: UnsafePointer<Int8>?) -> CSSStyleSheet in
        let ref = _CSSStyleSheetCreateFromNode(node.reference, nameCstr, contentsCstr)
        //print("_CSSStyleSheetCreateFromNode \(ref!)")
        return CSSStyleSheet(reference: ref!)
      }
    }
  }

  init(reference: CSSStyleSheetRef) {
    self.reference = reference
  }

  deinit {
    _CSSStyleSheetDestroy(reference)
  }

  public func clearOwnerNode() {
    _CSSStyleSheetClearOwnerNode(reference)
  }

  public func clearOwnerRule() {
    _CSSStyleSheetClearOwnerRule(reference) 
  }

  public func insertRule(rule: String, index: Int) -> Int {
    return rule.withCString { (cstr: UnsafePointer<Int8>?) -> Int in
      return Int(_CSSStyleSheetInsertRule(reference, cstr, CInt(index)))
    }
  }

  public func addRule(selector: String, style: String, index: Int) -> Int {
    return selector.withCString { (selCstr: UnsafePointer<Int8>?) -> Int in
      return style.withCString { (styleCstr: UnsafePointer<Int8>?) -> Int in
        return Int(_CSSStyleSheetAddRuleIndex(reference, selCstr, styleCstr, CInt(index)))
      }
    }
  }

  public func addRule(selector: String, style: String) -> Int {
    return selector.withCString { (selCstr: UnsafePointer<Int8>?) -> Int in
      return style.withCString { (styleCstr: UnsafePointer<Int8>?) -> Int in
        return Int(_CSSStyleSheetAddRule(reference, selCstr, styleCstr))
      }
    } 
  }
  
  public func deleteRule(index: Int) {
    _CSSStyleSheetDeleteRule(reference, CInt(index))
  }
  
  public func item(index: Int) -> CSSRule? {
    let ref = _CSSStyleSheetGetItem(reference, CInt(index))
    return ref != nil ? CSSRule(reference: ref!) : nil
  }

  public func willMutateRules() {
    _CSSStyleSheetWillMutateRules(reference)
  }
  
  public func didMutateRules() {
    _CSSStyleSheetDidMutateRules(reference)
  }
  
  public func didMutate() {
    _CSSStyleSheetDidMutate(reference)
  }

  public func startLoadingDynamicSheet() {
    _CSSStyleSheetStartLoadingDynamicSheet(reference)
  }

  public func setText(text: String) {
    text.withCString {
      _CSSStyleSheetSetText(reference, $0)
    }
  }
  
  public func setAlternateFromConstructor(_ alternate: Bool) {
    _CSSStyleSheetSetAlternateFromConstructor(reference, alternate ? 1 : 0)
  }
  
  public func canBeActivated(_ currentPreferrableName: String) -> Bool {
    return currentPreferrableName.withCString { (cstr: UnsafePointer<Int8>?) -> Bool in
      return _CSSStyleSheetCanBeActivated(reference, cstr) != 0
    }
  }

}

public class CSSStyleSheetList {

  var reference: CSSStyleSheetListRef
  // we keep a cache here for (array) lifetime sake
  // giving we are passing the inner array buffer
  // as a collection pointer to the native references
  static var nativeRefs: UnsafeMutablePointer<UnsafeRawPointer?>?
    
  public static func create(_ styles: [CSSStyleSheet]) -> CSSStyleSheetList {
    CSSStyleSheetList.nativeRefs = UnsafeMutablePointer<UnsafeRawPointer?>.allocate(capacity: styles.count)
    for i in 0..<styles.count {
      //print("_CSSStyleSheetListCreate \(styles[i].reference)")
      (CSSStyleSheetList.nativeRefs! + i).initialize(to: styles[i].reference)
    }
    return CSSStyleSheetList(reference: _CSSStyleSheetListCreate(CSSStyleSheetList.nativeRefs!, CInt(styles.count)))
  }

  init(reference: CSSStyleSheetListRef) {
    self.reference = reference
  }

  deinit {
    if let refs = CSSStyleSheetList.nativeRefs {
      refs.deallocate()
    }
  }

}